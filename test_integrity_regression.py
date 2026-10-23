#!/usr/bin/env python3
"""
別視点のテスト(標準ライブラリのみ):
  B. 内部整合性 / ラウンドトリップ・差分: ツールが自己矛盾しないことを検証
  C. 回帰 / スナップショット:            既知入力への判定が将来も変わらないことを保証
    python3 test_integrity_regression.py
"""
import base64
import csv
import io
import os
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import php_malware_scan as m
import link_audit as la


def scan(files: dict, **kw):
    d = tempfile.mkdtemp()
    for name, content in files.items():
        p = Path(d) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    opts = dict(exclude=m.DEFAULT_EXCLUDE, max_size=5_000_000, since=None,
                unpack_dir=None, scan_all=False, quiet=True, strict=False)
    opts.update(kw)
    sc = m.Scanner(Path(d), **opts)
    sc.walk()
    return sc, d


def finding_set(sc):
    return {(f.severity, f.kind, f.path, f.detail) for f in sc.findings}


# ================= B. 内部整合性 / ラウンドトリップ・差分 =================

class IntegrityTests(unittest.TestCase):

    def test_all_decoders_roundtrip(self):
        """各デコード関数が、対応するエンコードの逆変換になっている"""
        data = b"<?php system($_POST['c']); // payload body here"
        self.assertEqual(m.DECODER_FUNCS["base64_decode"](base64.b64encode(data)), data)
        self.assertEqual(m.DECODER_FUNCS["gzinflate"](zlib.compress(data)[2:-4]), data)
        self.assertEqual(m.DECODER_FUNCS["gzuncompress"](zlib.compress(data)), data)
        self.assertEqual(m.DECODER_FUNCS["str_rot13"](m.DECODER_FUNCS["str_rot13"](data)), data)
        self.assertEqual(m.DECODER_FUNCS["strrev"](m.DECODER_FUNCS["strrev"](data)), data)
        self.assertEqual(m.DECODER_FUNCS["hex2bin"](data.hex().encode()), data)

    def test_severity_values_are_valid(self):
        """全ての検出の重大度は 高/中/低 のいずれか(未知の値が紛れない)"""
        sc, _ = scan({
            "a.php": '<?php eval($_POST["x"]);',
            "b.php": '<?php eval(base64_decode("' + "QUJD" * 50 + '"));',
            "wp-content/uploads/c.php": "<?php echo 1;",
        })
        for f in sc.findings:
            self.assertIn(f.severity, ("高", "中", "低"), f"未知の重大度: {f.severity}")

    def test_strict_is_subset_across_many(self):
        """strictの検出集合は、常に通常モードの検出集合に含まれる(多数例で)"""
        cases = [
            '<?php eval($_POST["x"]);',
            '<?php eval(gzinflate(base64_decode("' + "QUJD" * 80 + '")));',
            '<?php preg_replace("/.*/e", $_POST["c"], "");',
            '<?php $x=base64_decode($y); $x();',
            '<?php /* FilesMan */ system($_GET["c"]);',
            '<?php include($_GET["p"]);',
        ]
        for code in cases:
            normal = finding_set(scan({"f.php": code})[0])
            strict = finding_set(scan({"f.php": code}, strict=True)[0])
            # strictは重大度を下げるので「高」の集合で比較
            nh = {x for x in normal if x[0] == "高"}
            sh = {x for x in strict if x[0] == "高"}
            self.assertTrue(sh <= nh, f"strict高が通常高に含まれない: {code}\n  strictのみ: {sh - nh}")

    def test_csv_roundtrip(self):
        """report() が書くCSVは、正しく読み戻せる(列ずれ・壊れがない)"""
        sc, d = scan({"a.php": '<?php eval($_POST["x"]);'})
        out = os.path.join(d, "r.csv")
        high = sc.report(out)
        with open(out, encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(set(rows[0].keys()), {"重要度", "種別", "ファイル", "詳細", "層", "展開ファイル"})
        # 「高」の件数がreport戻り値と一致
        self.assertEqual(sum(1 for r in rows if r["重要度"] == "高"),
                         sum(1 for f in sc.findings if f.severity == "高"))

    def test_report_return_matches_findings(self):
        """report() の戻り値(高の件数)は findings の高の数と一致する"""
        sc, d = scan({"a.php": '<?php eval($_POST["x"]);', "wp-content/uploads/b.php": "<?php echo 1;"})
        high = sc.report(os.path.join(d, "r.csv"))
        self.assertEqual(high, len({f.path for f in sc.findings if f.severity == "高"}))

    def test_exclude_empty_scans_more(self):
        """--exclude を空にすると、除外されていたファイルも走査対象になる(単調性)"""
        files = {"wp-includes/js/jquery.min.js": "eval(function(p,a,c,k,e,d){}('',1,1,''.split('|')))"}
        with_default, _ = scan(files)                 # min.js は除外
        without, _ = scan(files, exclude="")          # 除外なし
        self.assertLessEqual(with_default.files, without.files)

    def test_link_audit_baseline_symmetry(self):
        """link_audit: 同じ結果をbaselineにすると新規はゼロになる(差分の対称性)"""
        d = tempfile.mkdtemp()
        base = os.path.join(d, "base.csv")
        # 疑似的に findings を作ってCSV化 → 自分自身をbaselineに
        # (base, allow, max_pages, delay, timeout, insecure, ua, ignore_query, use_sitemap, exclude, quiet)
        a = la.Auditor("https://example.com", [], 10, 0, 5, False, la.DEFAULT_UA,
                       False, False, None, True)
        a.add("https://example.com", "高", "隠しリンク", "https://x.example/", "t")
        a.report(base, False)
        n = a.apply_baseline(base)
        self.assertEqual(n, 0, "同一結果をbaselineにしたら新規は0のはず")


# ================= C. 回帰 / スナップショット =================

class RegressionTests(unittest.TestCase):
    """既知の入力に対する判定を固定。将来コードを変えて挙動が変わったら気づける。
    (値が変わった=退行の可能性。意図的な変更ならこのテストを更新する)"""

    # (ファイル, 中身, 期待する最高重大度)  ※検体は無害な模擬
    KNOWN_MALWARE = [
        ("eval_post.php", '<?php @eval($_POST["x"]);', "高"),
        ("eval_b64.php", '<?php eval(base64_decode("' + base64.b64encode(b"<?php system($_GET[0]);"*3).decode() + '"));', "高"),
        ("preg_e.php", '<?php preg_replace("/.*/e", $_POST["c"], "");', "高"),
        ("include_req.php", '<?php include($_GET["page"]);', "高"),
        ("varfunc.php", '<?php $f="sys"."tem"; $f($_POST["c"]);', "高"),
        ("filesman.php", "<?php /* FilesMan */ move_uploaded_file($_FILES['f']['tmp_name'],'x');", "高"),
        ("gif_shell.php", b"GIF89a<?php assert($_POST['c']);", "高"),
    ]

    KNOWN_CLEAN = [
        ("l10n.php", "<?php return ['x-generator'=>'GlotPress/4.1.0','messages'=>['a'=>'b']];"),
        ("functions.php", "<?php add_action('init', function(){ register_post_type('x'); }); $o=get_option('y');"),
        ("curl.php", "<?php $ch=curl_init($url); curl_setopt($ch,CURLOPT_RETURNTRANSFER,1); $r=curl_exec($ch);"),
        ("preg_normal.php", "<?php $s=preg_replace('/\\\\s+/i',' ',$x); $a=array_map('trim',$list);"),
        ("new_class.php", '<?php $obj = new $handler_class($config); return $obj->run();'),
        # WordPress本体 wp-settings.php の627行目(実物)。コメント内の $_REQUEST ( $_GET + $_POST ) を
        # 可変関数バックドアと誤検出していた回帰ケース
        ("wp_settings_comment.php",
         "<?php\n// Add magic quotes and set up $_REQUEST ( $_GET + $_POST ).\nwp_magic_quotes();"),
        # 同系: スーパーグローバルを関数のように書いたコメント/文字列は誤検出しない
        ("superglobal_text.php",
         "<?php /* uses $_POST (user input) and $_GET (query) */ echo 1;"),
    ]

    def _max_sev(self, sc):
        order = {"高": 3, "中": 2, "低": 1}
        return max((order.get(f.severity, 0) for f in sc.findings), default=0)

    def test_known_malware_stays_high(self):
        for name, body, expect in self.KNOWN_MALWARE:
            sc, _ = scan({name if "/" in name else f"wp-content/uploads/{name}": body})
            has_high = any(f.severity == "高" for f in sc.findings)
            self.assertTrue(has_high, f"既知マルウェア {name} が「高」でなくなった(退行の疑い)")

    def test_known_clean_stays_clean(self):
        for name, body in self.KNOWN_CLEAN:
            sc, _ = scan({f"wp-content/plugins/x/{name}": body})
            has_high = any(f.severity == "高" for f in sc.findings)
            self.assertFalse(has_high, f"正規ファイル {name} が「高」になった(誤検出の退行)")

    def test_detection_kinds_snapshot(self):
        """代表的なマルウェアで、検出される『種別』の集合を固定(新種別の増減に気づく)"""
        sc, _ = scan({"wp-content/uploads/shell.php":
                      '<?php @eval($_POST["x"]); system($_GET["c"]);'})
        kinds = {f.kind for f in sc.findings if f.severity == "高"}
        # 最低限これらは含まれるべき(将来 kind 名を変えたら気づく)
        self.assertIn("uploads内のPHP", kinds)
        self.assertTrue(any("バックドア" in k for k in kinds),
                        f"バックドア系の種別が消えた: {kinds}")

    def test_multilayer_depth_snapshot(self):
        """3層難読化が、各層を剥がして最深部のバックドアに到達する"""
        body = b'<?php @eval($_POST["z"]);'
        l1 = base64.b64encode(body)
        l2 = base64.b64encode(zlib.compress(b'<?php eval(base64_decode("'+l1+b'"));')[2:-4])
        code = '<?php eval(gzinflate(base64_decode("' + l2.decode() + '")));'
        sc, _ = scan({"wp-content/uploads/x.php": code}, unpack_dir=Path(tempfile.mkdtemp()))
        # 展開系の検出があり、受け口 z に到達している
        expanded = [f for f in sc.findings if "展開" in f.kind]
        self.assertTrue(expanded, "多層展開の検出が消えた")
        self.assertTrue(any("z" in f.detail for f in sc.findings),
                        "最深部の受け口 z に到達できていない")


class LocaleNoteTests(unittest.TestCase):
    """version.php等ロケールで変わりうる本体ファイルの改変には、補記が付く"""

    def _compare(self, relpath, actual_body, official_md5):
        import tempfile as tf
        d = tf.mkdtemp()
        p = Path(d) / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(actual_body)
        sc = m.Scanner(Path(d), exclude=m.DEFAULT_EXCLUDE, max_size=5_000_000, since=None,
                       unpack_dir=None, scan_all=False, quiet=True)
        sc.compare_core({relpath: official_md5}, "7.0.2")
        return [f for f in sc.findings if f.kind == "本体ファイル改変" and relpath in f.path]

    def test_version_php_has_locale_note(self):
        found = self._compare("wp-includes/version.php", "<?php $wp_version='7.0.2';", "0"*32)
        self.assertTrue(found, "version.phpの改変は検出される")
        self.assertIn("ロケール", found[0].detail, "version.phpにはロケール差の補記が付く")

    def test_normal_core_file_no_locale_note(self):
        found = self._compare("wp-includes/load.php", "<?php // tampered", "0"*32)
        self.assertTrue(found)
        self.assertNotIn("ロケール", found[0].detail, "通常の本体ファイルには補記を付けない")


if __name__ == "__main__":
    unittest.main(verbosity=2)
