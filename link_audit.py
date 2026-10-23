#!/usr/bin/env python3
"""
link_audit.py - 自分のサイトを巡回して不審なリンクを洗い出すクローラー (v4 / 標準ライブラリのみ)

Python 3.9 以上であれば追加ライブラリ無しで動きます。

使い方:
    python3 link_audit.py https://example.com
    python3 link_audit.py https://example.com --allow cdn.example.com --max-pages 500
    python3 link_audit.py https://example.com --baseline 前回.csv --new-only
    python3 link_audit.py https://example.com --user-agent googlebot --out as_googlebot.csv

終了コード: 0 = 重要度「高」なし / 1 = 重要度「高」あり / 2 = 起動エラー
(cron で `|| mail ...` のように使えます)

主な機能:
    - 自ドメイン内のページを辿る(sitemap.xml / robots.txt の Sitemap も起点。gzip圧縮にも対応)
    - 外部リンク・隠しリンク(インラインstyle / hidden属性 / <style>内の単純なクラス・ID指定)
    - スパム語句・javascript:/data: リンク・短縮URL・IP直指定・Punycode
    - 外部 script / iframe / form action / canonical / <base href> の差し替え
    - meta refresh、インラインJSによる転送、難読化スクリプト疑い
    - 内部リンクの 4xx/5xx、内部URLが外部へ転送される事象(外部へは追いかけず、転送先だけ記録)
    - 同じ検出はURL単位にまとめ、出現ページ数を添える
    - --baseline で前回CSVと比較し、新規検出に印を付ける(--new-only で新規のみ出力)
    - --user-agent googlebot でクローキング(検索エンジンにだけ見せる改ざん)の確認
    - Ctrl-C で中断しても、そこまでの結果をCSVに書き出す

既知の限界:
    - 外部CSSファイルや複雑なセレクタ(.a .b{display:none})による非表示は検出しない
    - JavaScriptで後から挿入されるリンクは検出しない(HTMLを静的に読むため)
"""

from __future__ import annotations

import argparse
import csv
import gzip
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable, Optional
from urllib.parse import quote, urljoin, urlparse, urlunparse

DEFAULT_UA = "LinkAuditBot/4.0 (self-site security audit)"
UA_PRESETS = {
    "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "iphone": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
}
MAX_HTML_BYTES = 5 * 1024 * 1024
DEFAULT_EXCLUDE = r"/wp-admin/|/wp-login\.php|[?&]replytocom=|/feed/?$|/xmlrpc\.php"

# ---------- 判定用の定数 ----------

SPAM_WORDS_EN = [
    "casino", "viagra", "cialis", "levitra", "poker", "betting", "slots?",
    "payday", "loans?", "pharmacy", "replica", "escort", "porn", "xxx",
    "jackpot", "adult", "free[- ]?bonus", "crypto[- ]?bonus",
]
SPAM_RE_EN = re.compile(r"\b(?:" + "|".join(SPAM_WORDS_EN) + r")\b", re.I)
SPAM_WORDS_JA = [
    "カジノ", "オンカジ", "パチスロ", "バイアグラ", "シアリス", "出会い系",
    "セフレ", "風俗", "スーパーコピー", "偽物", "即日融資", "闇金",
    "アダルト", "ブランドコピー", "裏DVD",
]
SHORTENERS = {
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "t.ly", "x.gd", "urx.red", "ux.nu",
}
HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|rem)?(?![.\d])"
    r"|opacity\s*:\s*0(?![.\d])|(?:left|top|text-indent)\s*:\s*-\d{3,}",
    re.I,
)
# <style> 内で「単純なクラス/ID だけのセレクタ」に非表示指定があるものを拾う
CSS_RULE = re.compile(r"([^{}]+)\{([^{}]*)\}")
SIMPLE_SELECTOR = re.compile(r"^\s*([.#])([\w-]+)\s*$")
IP_HOST = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
REDIRECT_JS = re.compile(
    r"(?:location\s*\.\s*(?:href|replace|assign)|window\s*\.\s*location|document\s*\.\s*location)\s*[=(]",
    re.I,
)
OBFUSCATED_JS = re.compile(r"\b(?:eval|atob|unescape|String\.fromCharCode)\s*\(", re.I)
URL_IN_TEXT = re.compile(r"https?://[^\s'\"<>)]+", re.I)
META_CHARSET = re.compile(rb"charset\s*=\s*[\"']?\s*([a-zA-Z0-9_\-]+)", re.I)
SEVERITY_ORDER = {"高": 0, "中": 1, "低": 2}

VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
             "meta", "param", "source", "track", "wbr"}
# 閉じ忘れを吸収する暗黙クローズ: 開始タグ → (閉じる対象, 探索を止める親)
BLOCK_CONTAINERS = {"div", "section", "article", "aside", "nav", "header", "footer", "main",
                    "body", "html", "td", "th", "li", "blockquote", "form", "figure", "dd", "dt"}
IMPLICIT_CLOSE = {
    "p": ({"p"}, BLOCK_CONTAINERS),
    "li": ({"li"}, {"ul", "ol", "menu"}),
    "dt": ({"dt", "dd"}, {"dl"}), "dd": ({"dt", "dd"}, {"dl"}),
    "tr": ({"tr"}, {"table", "tbody", "thead", "tfoot"}),
    "td": ({"td", "th"}, {"tr", "table"}), "th": ({"td", "th"}, {"tr", "table"}),
    "option": ({"option"}, {"select", "datalist", "optgroup"}),
}
# これらの開始タグは開いている p を閉じる
CLOSES_P = {"address", "article", "aside", "blockquote", "div", "dl", "fieldset", "figure",
            "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "main",
            "nav", "ol", "pre", "section", "table", "ul", "p"}


# ---------- 小道具 ----------

def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def root_host(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def spam_hit(text: str) -> str:
    m = SPAM_RE_EN.search(text)
    if m:
        return m.group(0)
    for w in SPAM_WORDS_JA:
        if w in text:
            return w
    return ""


def iri_to_uri(url: str) -> str:
    """日本語を含むURL(IRI)を urllib が扱える形に変換する"""
    p = urlparse(url)
    host = p.hostname or ""
    try:
        host_ascii = host.encode("idna").decode("ascii") if not host.isascii() else host
    except UnicodeError:
        host_ascii = host
    netloc = host_ascii
    if p.port:
        netloc += f":{p.port}"
    path = quote(p.path, safe="/%:@&=+$,;~!*'()[]")
    query = quote(p.query, safe="=&%+/?:@;,~!*'()$[]")
    return urlunparse((p.scheme, netloc, path, p.params, query, ""))


def decode_html(raw: bytes, content_type: str) -> str:
    """文字コード判定。ヘッダが latin-1 系なら meta charset を優先し、UTF-8 を先に試す"""
    header_enc = meta_enc = None
    m = re.search(r"charset\s*=\s*[\"']?([a-zA-Z0-9_\-]+)", content_type or "", re.I)
    if m:
        header_enc = m.group(1).lower()
    m2 = META_CHARSET.search(raw[:4096])
    if m2:
        meta_enc = m2.group(1).decode("ascii", "ignore").lower()
    cands: list[str] = []
    if header_enc and header_enc not in ("iso-8859-1", "latin-1", "latin1", "ascii", "us-ascii"):
        cands.append(header_enc)
    if meta_enc:
        cands.append(meta_enc)
    cands += ["utf-8", "cp932", "euc-jp"]
    for enc in cands:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


# ---------- HTML 解析 ----------

@dataclass
class Elem:
    tag: str
    attrs: dict
    hidden: bool            # 自身または祖先がインラインで隠されている
    noscript: bool
    selectors: frozenset    # 自身と祖先の .class / #id の集合
    text: list = field(default_factory=list)
    href: str = ""


@dataclass
class Anchor:
    href: str
    text: str
    hidden: bool
    noscript: bool
    selectors: frozenset


class PageParser(HTMLParser):
    """1ページ分を読み、監査に必要な要素だけ集める"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[Elem] = []
        self.base_href: Optional[str] = None
        self.canonicals: list[str] = []
        self.meta_refresh: list[str] = []
        self.script_srcs: list[str] = []
        self.script_bodies: list[str] = []
        self.style_bodies: list[str] = []
        self.iframes: list[tuple[str, bool, frozenset]] = []
        self.forms: list[str] = []
        self.anchors: list[Anchor] = []
        self._cdata_buf: Optional[list[str]] = None
        self._cdata_kind = ""

    # --- 状態 ---
    @staticmethod
    def _self_hidden(attrs: dict) -> bool:
        if "hidden" in attrs:
            return True
        style = attrs.get("style") or ""
        return bool(style and HIDDEN_STYLE.search(style))

    @staticmethod
    def _self_selectors(attrs: dict) -> set:
        s = {"." + c for c in (attrs.get("class") or "").split()}
        if attrs.get("id"):
            s.add("#" + attrs["id"].strip())
        return s

    def _record_anchor(self, e: Elem) -> None:
        if e.tag == "a" and e.href:
            self.anchors.append(Anchor(e.href, " ".join("".join(e.text).split()),
                                       e.hidden, e.noscript, e.selectors))

    def _close_from(self, i: int) -> None:
        for e in self.stack[i:]:
            self._record_anchor(e)
        del self.stack[i:]

    def _implicit_close(self, tag: str) -> None:
        rule = IMPLICIT_CLOSE.get(tag)
        if rule:
            targets, stops = rule
            for i in range(len(self.stack) - 1, -1, -1):
                t = self.stack[i].tag
                if t in targets:
                    self._close_from(i)
                    break
                if t in stops:
                    break
        if tag in CLOSES_P:
            for i in range(len(self.stack) - 1, -1, -1):
                t = self.stack[i].tag
                if t == "p":
                    self._close_from(i)
                    break
                if t in BLOCK_CONTAINERS:
                    break

    # --- イベント ---
    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        self._implicit_close(tag)
        parent = self.stack[-1] if self.stack else None
        hidden = (parent.hidden if parent else False) or self._self_hidden(a)
        noscript = (parent.noscript if parent else False) or tag == "noscript"
        selectors = frozenset((parent.selectors if parent else frozenset()) | self._self_selectors(a))

        if tag == "base" and a.get("href") and self.base_href is None:
            self.base_href = a["href"].strip()
        elif tag == "link":
            rels = (a.get("rel") or "").lower().split()
            if "canonical" in rels and a.get("href"):
                self.canonicals.append(a["href"].strip())
        elif tag == "meta":
            if (a.get("http-equiv") or "").lower() == "refresh":
                self.meta_refresh.append(a.get("content") or "")
        elif tag == "script":
            if a.get("src"):
                self.script_srcs.append(a["src"].strip())
                self._cdata_buf, self._cdata_kind = None, ""
            else:
                self._cdata_buf, self._cdata_kind = [], "script"
        elif tag == "style":
            self._cdata_buf, self._cdata_kind = [], "style"
        elif tag == "iframe":
            if a.get("src"):
                self.iframes.append((a["src"].strip(), hidden, selectors))
        elif tag == "form":
            if a.get("action"):
                self.forms.append(a["action"].strip())

        if tag in VOID_TAGS:
            return
        e = Elem(tag, a, hidden, noscript, selectors)
        if tag == "a":
            e.href = (a.get("href") or "").strip()
        self.stack.append(e)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._cdata_buf is not None:
            body = "".join(self._cdata_buf)
            (self.script_bodies if self._cdata_kind == "script" else self.style_bodies).append(body)
            self._cdata_buf, self._cdata_kind = None, ""
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i].tag == tag:
                self._close_from(i)
                break

    def handle_data(self, data):
        if self._cdata_buf is not None:
            self._cdata_buf.append(data)
            return
        for e in reversed(self.stack):
            if e.tag == "a":
                e.text.append(data)
                break

    def close(self):
        super().close()
        self._close_from(0)

    def hidden_selectors(self) -> set:
        """<style> 内の `.foo{display:none}` のような単純ルールから非表示セレクタを集める"""
        found: set = set()
        for css in self.style_bodies:
            css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
            for sel, body in CSS_RULE.findall(css):
                if not HIDDEN_STYLE.search(body):
                    continue
                for part in sel.split(","):
                    m = SIMPLE_SELECTOR.match(part)
                    if m:
                        found.add(m.group(1) + m.group(2))
        return found


# ---------- 検出結果 ----------

@dataclass
class Finding:
    severity: str
    kind: str
    url: str
    detail: str
    pages: list = field(default_factory=list)
    is_new: bool = False

    @property
    def key(self):
        return (self.kind, self.url, "" if self.url else self.detail)


# ---------- HTTP ----------

@dataclass
class Resp:
    status: int
    url: str
    content_type: str
    body: bytes
    location: str = ""      # 3xx で止めたときの転送先
    truncated: bool = False


class _NoExternalRedirect(urllib.request.HTTPRedirectHandler):
    """自サイト外への転送は追いかけず、3xx のまま返す"""

    def __init__(self, is_internal: Callable[[str], bool]):
        super().__init__()
        self._is_internal = is_internal

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self._is_internal(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Http:
    def __init__(self, ua: str, timeout: float, insecure: bool, is_internal: Callable[[str], bool]):
        self.timeout = timeout
        self.headers = {"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                        "Accept-Language": "ja,en;q=0.8"}
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx), _NoExternalRedirect(is_internal))

    @staticmethod
    def _readable(ctype: str, url: str) -> bool:
        c = ctype.lower()
        return any(k in c for k in ("html", "xml", "text/", "gzip")) or url.endswith(".gz")

    def get(self, url: str) -> Resp | Exception:
        try:
            req = urllib.request.Request(iri_to_uri(url), headers=self.headers)
            with self.opener.open(req, timeout=self.timeout) as r:
                ctype = r.headers.get("Content-Type", "")
                body, truncated = b"", False
                if self._readable(ctype, url):
                    body = r.read(MAX_HTML_BYTES + 1)
                    if len(body) > MAX_HTML_BYTES:
                        body, truncated = body[:MAX_HTML_BYTES], True
                return Resp(r.status, r.geturl(), ctype, body, truncated=truncated)
        except urllib.error.HTTPError as e:
            hdrs = e.headers
            return Resp(e.code, url, hdrs.get("Content-Type", "") if hdrs else "", b"",
                        location=(hdrs.get("Location", "") if hdrs else ""))
        except Exception as e:  # URLError, timeout, ssl, UnicodeError など
            return e


# ---------- 本体 ----------

class Auditor:
    def __init__(self, base: str, allow: list, max_pages: int, delay: float, timeout: float,
                 insecure: bool, ua: str, ignore_query: bool, use_sitemap: bool,
                 exclude: Optional[str], quiet: bool):
        self.base = base
        self.base_root = root_host(host_of(base))
        if not self.base_root:
            raise ValueError(f"起点URLが不正です: {base}")
        self.allow_roots = {self.base_root} | {root_host(a.lower()) for a in allow if a}
        self.max_pages = max_pages
        self.delay = delay
        self.ignore_query = ignore_query
        self.use_sitemap = use_sitemap
        self.exclude = re.compile(exclude) if exclude else None
        self.quiet = quiet
        self.http = Http(ua, timeout, insecure, self.is_internal)

        self.queue: deque = deque()
        self.queued: set = set()
        self.visited: set = set()
        self.findings: dict = {}
        self.pages = 0
        self.enqueue(self.normalize(base))

    # --- URL ---
    def normalize(self, url: str) -> str:
        p = urlparse(url)
        scheme = p.scheme.lower()
        netloc = (p.hostname or "").lower()
        try:
            port = p.port
        except ValueError:
            port = None
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            netloc += f":{port}"
        path = p.path or "/"
        query = "" if self.ignore_query else p.query
        return urlunparse((scheme, netloc, path, "", query, ""))

    def is_internal(self, url: str) -> bool:
        return root_host(host_of(url)) == self.base_root

    def is_allowed(self, url: str) -> bool:
        h = root_host(host_of(url))
        if h == "":
            return True
        return any(h == r or h.endswith("." + r) for r in self.allow_roots)

    def enqueue(self, url: str) -> None:
        if self.exclude and self.exclude.search(url):
            return
        if url not in self.queued and url not in self.visited:
            self.queued.add(url)
            self.queue.append(url)

    # --- 記録 ---
    def add(self, page: str, severity: str, kind: str, url: str, detail: str = "") -> None:
        f = Finding(severity, kind, url, detail)
        cur = self.findings.setdefault(f.key, f)
        if page not in cur.pages:
            cur.pages.append(page)

    def log(self, msg: str) -> None:
        if not self.quiet:
            print(msg, file=sys.stderr)

    # --- sitemap ---
    def seed_from_sitemap(self) -> None:
        candidates = [urljoin(self.base, "/sitemap.xml"), urljoin(self.base, "/sitemap_index.xml")]
        r = self.http.get(urljoin(self.base, "/robots.txt"))
        if not isinstance(r, Exception) and r.status == 200 and r.body:
            for line in r.body.decode("utf-8", "replace").splitlines():
                if line.lower().startswith("sitemap:"):
                    candidates.append(line.split(":", 1)[1].strip())
        seen: set = set()
        added = 0

        def walk(url: str, depth: int = 0) -> None:
            nonlocal added
            if url in seen or depth > 3:
                return
            seen.add(url)
            r = self.http.get(url)
            if isinstance(r, Exception) or r.status != 200 or not r.body:
                return
            body = r.body
            if body[:2] == b"\x1f\x8b":
                try:
                    body = gzip.decompress(body)
                except OSError:
                    return
            try:
                root = ET.fromstring(body)
            except ET.ParseError:
                return
            is_index = root.tag.endswith("sitemapindex")
            for loc in root.iter():
                if loc.tag.endswith("}loc") or loc.tag == "loc":
                    u = (loc.text or "").strip()
                    if not u:
                        continue
                    if is_index:
                        walk(u, depth + 1)
                    elif self.is_internal(u):
                        self.enqueue(self.normalize(u))
                        added += 1
                    else:
                        self.add(url, "中", "sitemap内の外部URL", u, "自サイトのsitemapに他ドメインのURL")

        for c in candidates:
            walk(c)
        if added:
            self.log(f"sitemap から {added} 件のURLを起点に追加")

    # --- 1ページ解析 ---
    def inspect(self, page_url: str, html: str) -> None:
        p = PageParser()
        try:
            p.feed(html)
            p.close()
        except Exception as e:  # html.parser は寛容だが念のため
            self.add(page_url, "中", "解析失敗", page_url, str(e)[:120])
            return

        hidden_sel = p.hidden_selectors()
        resolve_base = page_url
        if p.base_href:
            bh = urljoin(page_url, p.base_href)
            if not self.is_internal(bh):
                self.add(page_url, "高", "外部base href", bh, "相対リンク全体が外部へ向く")
            resolve_base = bh

        for c in p.canonicals:
            cu = urljoin(resolve_base, c)
            if not self.is_internal(cu):
                self.add(page_url, "高", "外部canonical", cu, "正規URLが他ドメインを指す")

        for content in p.meta_refresh:
            target = ""
            mm = re.search(r"url\s*=\s*['\"]?([^'\"]+)", content, re.I)
            if mm:
                target = urljoin(resolve_base, mm.group(1).strip())
            sev = "高" if (target and not self.is_internal(target)) else "中"
            self.add(page_url, sev, "meta refresh", target or content, "自動転送")

        for src in p.script_srcs:
            full = urljoin(resolve_base, src)
            if not self.is_allowed(full):
                self.add(page_url, "高", "外部script", full, "許可リスト外のスクリプト読み込み")

        for body in p.script_bodies:
            if REDIRECT_JS.search(body):
                ext = [u for u in URL_IN_TEXT.findall(body) if not self.is_allowed(u)]
                if ext:
                    self.add(page_url, "高", "JSリダイレクト(外部)", ext[0], body.strip()[:120])
                else:
                    self.add(page_url, "中", "JSリダイレクト", "", body.strip()[:120])
            if OBFUSCATED_JS.search(body) and len(body) > 200:
                self.add(page_url, "高", "難読化スクリプト疑い", "", body.strip()[:120])

        for src, hidden, sels in p.iframes:
            full = urljoin(resolve_base, src)
            if not self.is_allowed(full):
                self.add(page_url, "高", "外部iframe", full, "許可リスト外のiframe")
            if hidden or (sels & hidden_sel):
                self.add(page_url, "高", "隠しiframe", full, "非表示のiframe")

        for action in p.forms:
            full = urljoin(resolve_base, action)
            if not self.is_allowed(full):
                self.add(page_url, "高", "外部form送信", full, "入力内容が他ドメインへ送られる")

        for an in p.anchors:
            try:
                scheme = urlparse(an.href).scheme.lower()
                if scheme in ("javascript", "data"):
                    self.add(page_url, "高", f"{scheme}:リンク", an.href[:150], an.text[:80])
                    continue
                if scheme in ("mailto", "tel", "sms"):
                    continue
                full = self.normalize(urljoin(resolve_base, an.href))
            except ValueError:
                self.add(page_url, "中", "不正なURL", an.href[:150], an.text[:80])
                continue
            h = host_of(full)
            spam = spam_hit(an.text + " " + full)
            label = an.text[:80] or "(テキスト無し)"
            css_hidden = bool(an.selectors & hidden_sel)
            hidden = an.hidden or css_hidden
            flagged = hidden or bool(spam) or an.noscript

            if hidden:
                how = "CSSクラス/IDで非表示" if (css_hidden and not an.hidden) else "インラインstyle/hidden属性で非表示"
                self.add(page_url, "高", "隠しリンク", full, f"{label} / {how}")
            if spam:
                self.add(page_url, "高", "スパム語句", full, f"語句:{spam} / 文言:{an.text[:60]}")
            if an.noscript and not self.is_internal(full):
                self.add(page_url, "中", "noscript内の外部リンク", full, label)
            if h in SHORTENERS:
                self.add(page_url, "中", "短縮URL", full, label); flagged = True
            if IP_HOST.match(h):
                self.add(page_url, "中", "IP直指定", full, label); flagged = True
            if "xn--" in h:
                self.add(page_url, "中", "Punycodeドメイン", full, label); flagged = True

            if self.is_internal(full):
                self.enqueue(full)
            elif not self.is_allowed(full) and not flagged:
                self.add(page_url, "低", "外部リンク", full, label)

    # --- メインループ ---
    def run(self) -> None:
        if self.use_sitemap:
            self.seed_from_sitemap()
        while self.queue and self.pages < self.max_pages:
            url = self.queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)
            self.pages += 1
            self.log(f"[{self.pages}] {url}")

            r = self.http.get(url)
            if isinstance(r, Exception):
                self.add(url, "中", "取得失敗", url, str(r)[:120])
                continue
            if 300 <= r.status < 400:
                target = urljoin(url, r.location) if r.location else "(転送先不明)"
                self.add(url, "高", "外部へリダイレクト", target, f"HTTP {r.status}: 内部URLが外部へ転送された")
                continue
            if r.status >= 400:
                self.add(url, "中", f"HTTP {r.status}", url, "内部リンク切れ/エラー")
                continue
            if r.url and not self.is_internal(r.url):
                self.add(url, "高", "外部へリダイレクト", r.url, "内部URLが外部へ転送された")
                continue
            if "html" not in r.content_type.lower() or not r.body:
                continue
            if r.truncated:
                self.add(url, "中", "ページが大きすぎる", url, f"{MAX_HTML_BYTES // 1024 // 1024}MBで打ち切り。後半は未検査")
            self.inspect(url, decode_html(r.body, r.content_type))
            time.sleep(self.delay)

    # --- 出力 ---
    def apply_baseline(self, path: str) -> int:
        try:
            with open(path, newline="", encoding="utf-8-sig") as f:
                old = {(row["種別"], row["URL"], "" if row["URL"] else row["詳細"])
                       for row in csv.DictReader(f)}
        except (FileNotFoundError, KeyError) as e:
            print(f"baseline を読めません({e}): {path}", file=sys.stderr)
            return 0
        n = 0
        for fnd in self.findings.values():
            if fnd.key not in old:
                fnd.is_new = True
                n += 1
        return n

    def report(self, out: str, new_only: bool) -> int:
        """CSVを書き、重要度「高」の件数を返す"""
        rows = sorted(self.findings.values(),
                      key=lambda x: (SEVERITY_ORDER[x.severity], x.kind, -len(x.pages), x.url))
        if new_only:
            rows = [x for x in rows if x.is_new]
        fields = ["重要度", "種別", "URL", "詳細", "出現ページ数", "初出ページ", "他ページ例", "新規"]
        with open(out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for x in rows:
                w.writerow({
                    "重要度": x.severity, "種別": x.kind, "URL": x.url, "詳細": x.detail,
                    "出現ページ数": len(x.pages),
                    "初出ページ": x.pages[0] if x.pages else "",
                    "他ページ例": " | ".join(x.pages[1:4]),
                    "新規": "新規" if x.is_new else "",
                })

        print("\n==== 結果 ====")
        print(f"巡回ページ数: {self.pages}  (未巡回キュー: {len(self.queue)})")
        for sev in ("高", "中", "低"):
            print(f"重要度 {sev}: {sum(1 for x in rows if x.severity == sev)} 件")
        print(f"\n詳細は {out} を参照")
        high = [x for x in rows if x.severity == "高"]
        if high:
            print("\n--- 重要度「高」の先頭10件 ---")
            for x in high[:10]:
                mark = "[新規] " if x.is_new else ""
                print(f"{mark}[{x.kind}] {x.pages[0]} (計{len(x.pages)}ページ)\n    -> {x.url}  {x.detail}")
        else:
            print("\n重要度「高」の検出はありませんでした。")
        return len(high)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="自サイトの不審リンク検出クローラー v4(標準ライブラリのみ)")
    ap.add_argument("base", help="起点URL(例: https://example.com)")
    ap.add_argument("--allow", nargs="*", default=[],
                    help="外部でも許可するドメイン。サブドメインも含めて許可(例: cdn.example.net)")
    ap.add_argument("--max-pages", type=int, default=300, help="巡回する最大ページ数")
    ap.add_argument("--delay", type=float, default=0.5, help="ページ間の待機秒数")
    ap.add_argument("--timeout", type=float, default=15, help="HTTPタイムアウト秒")
    ap.add_argument("--user-agent", default=DEFAULT_UA,
                    help="User-Agent。googlebot / chrome / iphone のプリセット名か任意の文字列")
    ap.add_argument("--insecure", action="store_true", help="SSL証明書を検証しない(自己署名のテスト環境用)")
    ap.add_argument("--ignore-query", action="store_true", help="?以降を無視して同一ページ扱いにする")
    ap.add_argument("--exclude", default=DEFAULT_EXCLUDE,
                    help=f"巡回しないURLの正規表現(既定: WordPressの管理画面・feed等)。空文字で無効化")
    ap.add_argument("--no-sitemap", action="store_true", help="sitemap.xml を起点に使わない")
    ap.add_argument("--baseline", help="前回の完全なCSV(--new-only で出したものは不可)。無い検出を「新規」と印付け")
    ap.add_argument("--new-only", action="store_true", help="--baseline と併用。新規検出だけを出力する")
    ap.add_argument("--out", default="link_audit_report.csv", help="出力CSVファイル名")
    ap.add_argument("--quiet", action="store_true", help="巡回ログを表示しない")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not args.base.startswith("http"):
        args.base = "https://" + args.base
    ua = UA_PRESETS.get(args.user_agent.lower(), args.user_agent)
    try:
        auditor = Auditor(args.base, args.allow, args.max_pages, args.delay, args.timeout,
                          args.insecure, ua, args.ignore_query, not args.no_sitemap,
                          args.exclude, args.quiet)
    except (ValueError, re.error) as e:
        print(f"エラー: {e}", file=sys.stderr)
        return 2
    try:
        auditor.run()
    except KeyboardInterrupt:
        print("\n中断されました。ここまでの結果を書き出します。", file=sys.stderr)
    if args.baseline:
        print(f"前回との比較: 新規 {auditor.apply_baseline(args.baseline)} 件")
    high = auditor.report(args.out, args.new_only and bool(args.baseline))
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
