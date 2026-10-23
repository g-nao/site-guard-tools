#!/usr/bin/env python3
"""
公開前の堅牢性テスト(TDD): 想定外の入力・実在の攻撃手法でクラッシュや取りこぼしがないか。
まず実行して落ちるものを特定し、php_malware_scan.py 側を直す。
    python3 test_robustness.py
"""
import base64
import os
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import php_malware_scan as m


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


def high_paths(sc):
    return {f.path.split(" [")[0] for f in sc.findings if f.severity == "高"}


class MalformedInputTests(unittest.TestCase):
    """壊れた入力でクラッシュしないこと"""

    def test_invalid_utf8(self):
        sc, _ = scan({"a.php": b"<?php \xff\xfe\x80 eval($_POST['x']); \x00\x01"})
        self.assertIn("a.php", high_paths(sc))  # 壊れたバイトがあってもバックドアは拾う

    def test_empty_file(self):
        sc, _ = scan({"a.php": b""})  # 例外が出なければ合格
        self.assertIsNotNone(sc)

    def test_only_php_tag(self):
        sc, _ = scan({"a.php": b"<?php"})
        self.assertIsNotNone(sc)

    def test_huge_single_line(self):
        sc, _ = scan({"a.php": "<?php $x='" + "A" * 500000 + "';"})
        self.assertIsNotNone(sc)  # 巨大1行で正規表現が爆発しないこと

    def test_deeply_nested_base64(self):
        # 20重のbase64。MAX_LAYERSで止まり、無限ループしないこと
        data = b'<?php eval($_POST["x"]);'
        for _ in range(20):
            data = base64.b64encode(data)
        sc, _ = scan({"a.php": b'<?php eval(base64_decode("' + data + b'"));'})
        self.assertIsNotNone(sc)

    def test_null_bytes_everywhere(self):
        sc, _ = scan({"a.php": b"<?php\x00 system($_GET\x00['c']);"})
        self.assertIsNotNone(sc)

    def test_binary_garbage_php_ext(self):
        sc, _ = scan({"a.php": bytes(range(256)) * 100})
        self.assertIsNotNone(sc)


class RealAttackTests(unittest.TestCase):
    """実在する攻撃手法を取りこぼさないこと"""

    def test_concatenated_function_name(self):
        # 'ba'.'se64_decode' のような文字列連結で関数名を隠す
        sc, _ = scan({"a.php": '<?php $f="sys"."tem"; $f($_POST["c"]);'})
        self.assertIn("a.php", high_paths(sc))

    def test_double_extension(self):
        # shell.php.jpg は多くのサーバーでPHP実行される
        sc, _ = scan({"wp-content/uploads/shell.php.jpg": "<?php eval($_POST['x']);"})
        hits = high_paths(sc)
        self.assertTrue(hits, "二重拡張子 .php.jpg のシェルを検出すべき")

    def test_get_concatenation_backdoor(self):
        # $_GET値を連結してevalする
        sc, _ = scan({"a.php": '<?php eval($_GET["a"].$_GET["b"]);'})
        self.assertIn("a.php", high_paths(sc))

    def test_variable_variable(self):
        # $$var 型
        sc, _ = scan({"a.php": '<?php $k="x"; $$k = $_POST["d"]; @eval($x);'})
        # 取りこぼしても落ちないこと(検出できれば尚良い)
        self.assertIsNotNone(sc)

    def test_preg_e_with_spaces(self):
        sc, _ = scan({"a.php": "<?php preg_replace ( '/.*/e' , $_POST['c'] , '' );"})
        self.assertIn("a.php", high_paths(sc))

    def test_assert_backdoor(self):
        sc, _ = scan({"a.php": '<?php assert($_REQUEST["cmd"]);'})
        self.assertIn("a.php", high_paths(sc))

    def test_base64_in_cookie(self):
        sc, _ = scan({"a.php": '<?php eval(base64_decode($_COOKIE["x"]));'})
        self.assertIn("a.php", high_paths(sc))


class SymlinkAndSpecialTests(unittest.TestCase):
    """シンボリックリンクや特殊ファイルで誤動作しないこと"""

    def test_symlink_skipped(self):
        d = tempfile.mkdtemp()
        (Path(d) / "real.php").write_text("<?php echo 1;")
        try:
            os.symlink(Path(d) / "real.php", Path(d) / "link.php")
        except OSError:
            self.skipTest("シンボリックリンク作成不可")
        sc = m.Scanner(Path(d), exclude=m.DEFAULT_EXCLUDE, max_size=5_000_000, since=None,
                       unpack_dir=None, scan_all=False, quiet=True)
        sc.walk()  # シンボリックリンクを二重処理せず落ちないこと
        self.assertIsNotNone(sc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
