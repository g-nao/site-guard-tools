#!/usr/bin/env python3
"""
allowlist(パス+ハッシュ方式の除外)のテスト。TDD: 先に仕様を固める。
    python3 test_allowlist.py
"""
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import php_malware_scan as m


def scan(files: dict, allowlist=None, **kw):
    d = tempfile.mkdtemp()
    for name, content in files.items():
        p = Path(d) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    al = None
    if allowlist is not None:
        al = os.path.join(d, "allow.txt")
        Path(al).write_text(allowlist)
    opts = dict(exclude=m.DEFAULT_EXCLUDE, max_size=5_000_000, since=None,
                unpack_dir=None, scan_all=False, quiet=True, strict=False, allowlist=al)
    opts.update(kw)
    sc = m.Scanner(Path(d), **opts)
    sc.walk()
    return sc, d


def highs(sc):
    return {f.path.split(" [")[0] for f in sc.findings if f.severity == "高"}


def sha256_of(text):
    return hashlib.sha256(text.encode("utf-8") if isinstance(text, str) else text).hexdigest()


class AllowlistTests(unittest.TestCase):

    def test_no_allowlist_still_detects(self):
        """allowlist未指定なら従来どおり検出する"""
        sc, _ = scan({"wp-content/uploads/x.php": "<?php echo 1;"})
        self.assertIn("wp-content/uploads/x.php", highs(sc))

    def test_allowlisted_file_suppressed(self):
        """パス+ハッシュが一致する検出は「高」から消える"""
        body = "<?php echo 1;"
        al = f"{sha256_of(body)}  wp-content/uploads/x.php\n"
        sc, _ = scan({"wp-content/uploads/x.php": body}, allowlist=al)
        self.assertNotIn("wp-content/uploads/x.php", highs(sc))

    def test_tampered_file_still_flagged(self):
        """許可登録後に中身が変わったら(ハッシュ不一致)除外されない=改ざん検知"""
        registered = "<?php echo 1;"               # 登録時の中身
        actual = "<?php eval($_POST['x']); echo 1;" # 実際は改ざんされている
        al = f"{sha256_of(registered)}  a.php\n"
        sc, _ = scan({"a.php": actual}, allowlist=al)
        self.assertIn("a.php", highs(sc), "ハッシュ不一致なら除外せず検出すべき")

    def test_wrong_path_not_suppressed(self):
        """ハッシュが合ってもパスが違えば除外しない"""
        body = "<?php eval($_POST['x']);"
        al = f"{sha256_of(body)}  other/path.php\n"
        sc, _ = scan({"a.php": body}, allowlist=al)
        self.assertIn("a.php", highs(sc))

    def test_comments_and_blanks_ignored(self):
        """allowlistの # 行と空行は無視される"""
        body = "<?php echo 1;"
        al = f"# コメント\n\n{sha256_of(body)}  wp-content/uploads/x.php\n"
        sc, _ = scan({"wp-content/uploads/x.php": body}, allowlist=al)
        self.assertNotIn("wp-content/uploads/x.php", highs(sc))

    def test_malformed_allowlist_line_skipped(self):
        """壊れた行があっても落ちず、正しい行は有効"""
        body = "<?php echo 1;"
        al = f"これは壊れた行\n{sha256_of(body)}  wp-content/uploads/x.php\nhash_only_no_path\n"
        sc, _ = scan({"wp-content/uploads/x.php": body}, allowlist=al)
        self.assertNotIn("wp-content/uploads/x.php", highs(sc))

    def test_nonexistent_allowlist_file(self):
        """指定したallowlistファイルが無くても落ちない(警告して続行)"""
        d = tempfile.mkdtemp()
        Path(d, "a.php").write_text("<?php echo 1;")
        sc = m.Scanner(Path(d), exclude=m.DEFAULT_EXCLUDE, max_size=5_000_000, since=None,
                       unpack_dir=None, scan_all=False, quiet=True, strict=False,
                       allowlist="/no/such/allowlist.txt")
        sc.walk()
        self.assertIsNotNone(sc)

    def test_suppressed_recorded_as_low(self):
        """除外された検出は、消すのではなく低として記録に残す(監査証跡)"""
        body = "<?php echo 1;"
        al = f"{sha256_of(body)}  wp-content/uploads/x.php\n"
        sc, _ = scan({"wp-content/uploads/x.php": body}, allowlist=al)
        suppressed = [f for f in sc.findings if "許可" in f.kind or "allowlist" in f.kind.lower()]
        self.assertTrue(suppressed, "除外は低として記録に残すべき(完全に消さない)")


class WriteAllowlistTests(unittest.TestCase):
    """--write-allowlist 相当: 現在の高をallowlist形式で書き出す"""

    def test_dump_allowlist_lines(self):
        """高の検出について『SHA256␣パス』の行を生成できる"""
        d = tempfile.mkdtemp()
        (Path(d) / "wp-content/uploads").mkdir(parents=True)
        body = "<?php __halt_compiler();"
        (Path(d) / "wp-content/uploads/s.php").write_bytes(body.encode())
        sc = m.Scanner(Path(d), exclude=m.DEFAULT_EXCLUDE, max_size=5_000_000, since=None,
                       unpack_dir=None, scan_all=False, quiet=True)
        sc.walk()
        lines = sc.allowlist_lines()
        self.assertTrue(any(line.endswith("wp-content/uploads/s.php") for line in lines))
        # 生成した行の先頭は実ファイルのSHA256
        for line in lines:
            h = line.split()[0]
            self.assertRegex(h, r"^[0-9a-f]{64}$")

    def test_generated_allowlist_suppresses(self):
        """生成したallowlistを使うと、その検出が高から消える(往復)"""
        d = tempfile.mkdtemp()
        (Path(d) / "wp-content/uploads").mkdir(parents=True)
        (Path(d) / "wp-content/uploads/s.php").write_bytes(b"<?php echo 1;")
        sc1 = m.Scanner(Path(d), exclude=m.DEFAULT_EXCLUDE, max_size=5_000_000, since=None,
                        unpack_dir=None, scan_all=False, quiet=True)
        sc1.walk()
        al = os.path.join(d, "allow.txt")
        Path(al).write_text("\n".join(sc1.allowlist_lines()) + "\n")
        sc2 = m.Scanner(Path(d), exclude=m.DEFAULT_EXCLUDE, max_size=5_000_000, since=None,
                        unpack_dir=None, scan_all=False, quiet=True, allowlist=al)
        sc2.walk()
        self.assertEqual(highs(sc2), set(), "生成したallowlistで高が消えるべき")


if __name__ == "__main__":
    unittest.main(verbosity=2)
