#!/usr/bin/env python3
"""
link_audit.py のテスト。追加ライブラリ不要。
    python3 test_link_audit.py
"""
import gzip
import http.server
import os
import socketserver
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import link_audit as la  # noqa: E402


class SiteServer:
    """一時ディレクトリを配信するローカルHTTPサーバー(リダイレクトも返せる)"""

    def __init__(self):
        self.dir = tempfile.mkdtemp()
        self.redirects = {}  # path -> Location
        self.ua_pages = {}   # path -> {ua_substring: html}

        srv = self

        class H(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **k):
                super().__init__(*a, directory=srv.dir, **k)

            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path in srv.redirects:
                    self.send_response(302)
                    self.send_header("Location", srv.redirects[self.path])
                    self.end_headers()
                    return
                if self.path in srv.ua_pages:
                    ua = self.headers.get("User-Agent", "")
                    for key, html in srv.ua_pages[self.path].items():
                        if key in ua:
                            body = html.encode("utf-8")
                            self.send_response(200)
                            self.send_header("Content-Type", "text/html; charset=utf-8")
                            self.send_header("Content-Length", str(len(body)))
                            self.end_headers()
                            self.wfile.write(body)
                            return
                super().do_GET()

        self.httpd = socketserver.TCPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def write(self, name, content, binary=False):
        p = Path(self.dir) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if binary else content.encode("utf-8"))

    def close(self):
        self.httpd.shutdown()


def run(base, **kw):
    opts = dict(allow=[], max_pages=50, delay=0, timeout=5, insecure=False, ua=la.DEFAULT_UA,
                ignore_query=False, use_sitemap=False, exclude=la.DEFAULT_EXCLUDE, quiet=True)
    opts.update(kw)
    a = la.Auditor(base, **opts)
    a.run()
    return a


def kinds(a):
    return {(f.kind, f.url) for f in a.findings.values()}


class ParserTests(unittest.TestCase):
    def parse(self, html):
        p = la.PageParser()
        p.feed(html)
        p.close()
        return p

    def test_implicit_p_close_does_not_leak_hidden(self):
        p = self.parse('<p style="display:none">x<p><a href="/a">visible</a>')
        self.assertEqual(len(p.anchors), 1)
        self.assertFalse(p.anchors[0].hidden, "閉じ忘れた隠しpの後のリンクを隠し扱いにしない")

    def test_li_implicit_close(self):
        p = self.parse('<ul><li style="display:none">x<li><a href="/b">ok</a></ul>')
        self.assertFalse(p.anchors[0].hidden)

    def test_hidden_inheritance(self):
        p = self.parse('<div style="display:none"><span><a href="/h">h</a></span></div><a href="/v">v</a>')
        self.assertEqual([(x.href, x.hidden) for x in p.anchors], [("/h", True), ("/v", False)])

    def test_css_class_hidden(self):
        p = self.parse('<style>.menu li:hover .sub{display:none} .zz { display : none }</style>'
                       '<div class="zz"><a href="/x">x</a></div><div class="sub"><a href="/y">y</a></div>')
        sel = p.hidden_selectors()
        self.assertEqual(sel, {".zz"}, "複雑なセレクタは無視し、単純なクラスだけ拾う")
        self.assertIn(".zz", p.anchors[0].selectors)
        self.assertNotIn(".zz", p.anchors[1].selectors)

    def test_script_body_and_style_separated(self):
        p = self.parse('<script>location.href="x"</script><style>a{color:red}</style><a href="/">t</a>')
        self.assertEqual(len(p.script_bodies), 1)
        self.assertEqual(len(p.style_bodies), 1)
        self.assertEqual(p.anchors[0].text, "t")

    def test_comment_links_ignored(self):
        p = self.parse('<!-- <a href="https://spam.example/">casino</a> --><a href="/">ok</a>')
        self.assertEqual([x.href for x in p.anchors], ["/"])

    def test_unclosed_anchor_recorded(self):
        p = self.parse('<a href="/open">text')
        self.assertEqual(p.anchors[0].text, "text")


class UtilTests(unittest.TestCase):
    def test_spam_word_boundary(self):
        self.assertEqual(la.spam_hit("timeslot sloan download"), "")
        self.assertEqual(la.spam_hit("free slots here"), "slots")
        self.assertEqual(la.spam_hit("スーパーコピー時計"), "スーパーコピー")

    def test_iri_to_uri(self):
        self.assertEqual(la.iri_to_uri("http://例え.jp/記事 1?q=値"),
                         "http://xn--r8jz45g.jp/%E8%A8%98%E4%BA%8B%201?q=%E5%80%A4")
        self.assertEqual(la.iri_to_uri("http://a.com/%E3%81%82"), "http://a.com/%E3%81%82", "二重エンコードしない")

    def test_decode_prefers_meta_over_latin1_header(self):
        raw = '<meta charset="shift_jis">カジノ'.encode("cp932")
        self.assertIn("カジノ", la.decode_html(raw, "text/html; charset=iso-8859-1"))

    def test_decode_utf8_before_cp932(self):
        self.assertEqual(la.decode_html("日本語".encode("utf-8"), "text/html"), "日本語")


class CrawlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = SiteServer()
        s = cls.s
        s.write("index.html", f"""<html><head><meta charset="utf-8">
<link rel="canonical" href="https://evil.example/x"></head><body>
<a href="/about.html">about</a>
<a href="https://github.com/">timeslot github</a>
<div style="display:none"><a href="https://casino-spam.example/">オンカジ</a></div>
<noscript><a href="https://tracker.example/">t</a></noscript>
<a href="javascript:void(0)">js</a><a href="http://1.2.3.4/">ip</a><a href="https://bit.ly/abc">short</a>
<a href="http://[bad">broken</a>
<a href="/記事/日本語.html">jp</a>
<a href="/missing.html">missing</a>
<a href="/wp-admin/edit.php">admin</a>
<a href="/go-external">go</a>
<a href="https://img.cdn-ok.net/x.png">cdn</a>
<form action="https://phish.example/post"></form>
<script>window.location.href="https://bad.example/";</script>
</body></html>""")
        s.write("about.html", '<html><body><a href="/">home</a><a href="/about.html?x=1">self</a></body></html>')
        s.write("記事/日本語.html", '<html><body><a href="https://viagra-shop.example/">buy</a></body></html>')
        s.write("sitemap.xml", '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                f'<url><loc>{s.base}/orphan.html</loc></url><url><loc>https://other.example/p</loc></url></urlset>')
        s.write("orphan.html", '<html><body><a href="https://replica-watch.example/">w</a></body></html>')
        s.write("sitemap_index.xml.gz", gzip.compress(
            f'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>{s.base}/sitemap.xml</loc></sitemap></sitemapindex>'.encode()), binary=True)
        s.write("robots.txt", f"User-agent: *\nSitemap: {s.base}/sitemap_index.xml.gz\n")
        s.redirects["/go-external"] = "https://malware.example/landing"
        s.ua_pages["/cloak.html"] = {
            "Googlebot": '<html><body><a href="https://payday-loans.example/">loan</a></body></html>',
            "": '<html><body>clean page</body></html>',
        }
        s.write("big.html", "<html><body>" + ("<p>x</p>" * 100000) + '<a href="https://late.example/">late</a></body></html>')

    @classmethod
    def tearDownClass(cls):
        cls.s.close()

    def test_detections(self):
        a = run(self.s.base, allow=["cdn-ok.net"])
        k = kinds(a)
        base = self.s.base
        self.assertIn(("外部canonical", "https://evil.example/x"), k)
        self.assertIn(("隠しリンク", "https://casino-spam.example/"), k)
        self.assertIn(("スパム語句", "https://casino-spam.example/"), k)
        self.assertIn(("noscript内の外部リンク", "https://tracker.example/"), k)
        self.assertIn(("javascript:リンク", "javascript:void(0)"), k)
        self.assertIn(("IP直指定", "http://1.2.3.4/"), k)
        self.assertIn(("短縮URL", "https://bit.ly/abc"), k)
        self.assertIn(("不正なURL", "http://[bad"), k)
        self.assertIn(("外部form送信", "https://phish.example/post"), k)
        self.assertIn(("JSリダイレクト(外部)", "https://bad.example/"), k)
        self.assertIn(("HTTP 404", f"{base}/missing.html"), k)
        self.assertIn(("外部へリダイレクト", "https://malware.example/landing"), k)
        self.assertIn(("外部リンク", "https://github.com/"), k)
        # 日本語URLのページを辿れている
        self.assertIn(("スパム語句", "https://viagra-shop.example/"), k)
        # --allow はサブドメインを含む
        self.assertNotIn(("外部リンク", "https://img.cdn-ok.net/x.png"), k)
        # 既定の exclude で wp-admin は巡回しない
        self.assertNotIn(f"{base}/wp-admin/edit.php", a.visited)
        # 別種別で検出済みの外部リンクは「低」に重複しない
        self.assertNotIn(("外部リンク", "https://bit.ly/abc"), k)
        # 外部転送先の本文は取得していない(転送先に接触しない)
        self.assertFalse(any(u.startswith("https://malware") for u in a.visited))

    def test_sitemap_gzip_index_and_robots(self):
        a = run(self.s.base, use_sitemap=True)
        k = kinds(a)
        self.assertIn(("スパム語句", "https://replica-watch.example/"), k, "robots→gz index→sitemap→孤立ページ")
        self.assertIn(("sitemap内の外部URL", "https://other.example/p"), k)

    def test_cloaking_detected_with_googlebot_ua(self):
        normal = run(f"{self.s.base}/cloak.html", max_pages=1)
        bot = run(f"{self.s.base}/cloak.html", max_pages=1, ua=la.UA_PRESETS["googlebot"])
        self.assertNotIn(("スパム語句", "https://payday-loans.example/"), kinds(normal))
        self.assertIn(("スパム語句", "https://payday-loans.example/"), kinds(bot))

    def test_truncation_reported(self):
        old = la.MAX_HTML_BYTES
        la.MAX_HTML_BYTES = 100_000
        try:
            a = run(f"{self.s.base}/big.html", max_pages=1)
        finally:
            la.MAX_HTML_BYTES = old
        self.assertTrue(any(f.kind == "ページが大きすぎる" for f in a.findings.values()))

    def test_ignore_query_and_max_pages(self):
        a = run(f"{self.s.base}/about.html", ignore_query=True, max_pages=2)
        self.assertNotIn(f"{self.s.base}/about.html?x=1", a.visited)
        self.assertLessEqual(a.pages, 2)

    def test_baseline_marks_new(self):
        a = run(self.s.base)
        out = os.path.join(self.s.dir, "base.csv")
        a.report(out, False)
        b = run(self.s.base)
        b.add(self.s.base, "高", "隠しリンク", "https://brand-new.example/", "x")
        self.assertEqual(b.apply_baseline(out), 1)
        self.assertTrue(next(f for f in b.findings.values() if f.url == "https://brand-new.example/").is_new)

    def test_exit_code(self):
        out = os.path.join(self.s.dir, "r.csv")
        self.assertEqual(la.main([f"{self.s.base}/about.html", "--no-sitemap", "--delay", "0",
                                  "--quiet", "--out", out, "--max-pages", "1"]), 0)
        self.assertEqual(la.main([self.s.base, "--no-sitemap", "--delay", "0", "--quiet", "--out", out]), 1)
        self.assertEqual(la.main(["http://", "--out", out]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
