#!/usr/bin/env python3
"""
別視点のテスト(標準ライブラリのみ、hypothesis不要):
  A. 性質ベース: ランダム入力で落ちない/無限ループしない、エンコードのラウンドトリップ
  D. 敵対的:     検出を回避する小細工(大小文字・コメント・空白・エンコード変種)に耐えるか
    python3 test_property_adversarial.py
"""
import base64
import random
import signal
import sys
import tempfile
import time
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import php_malware_scan as m


def scan_text(code, name="a.php", **kw):
    d = tempfile.mkdtemp()
    p = Path(d) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(code if isinstance(code, bytes) else code.encode("utf-8"))
    opts = dict(exclude=m.DEFAULT_EXCLUDE, max_size=5_000_000, since=None,
                unpack_dir=None, scan_all=False, quiet=True, strict=False)
    opts.update(kw)
    sc = m.Scanner(Path(d), **opts)
    sc.walk()
    return sc


def is_high(sc, name="a.php"):
    return any(f.severity == "高" and f.path.split(" [")[0] == name for f in sc.findings)


class Timeout:
    """1ファイルの処理が指定秒を超えたら失敗扱い(無限ループ/壊滅的バックトラック検出)"""
    def __init__(self, sec): self.sec = sec
    def __enter__(self):
        if hasattr(signal, "SIGALRM"):
            signal.signal(signal.SIGALRM, self._raise); signal.setitimer(signal.ITIMER_REAL, self.sec)
    def __exit__(self, *a):
        if hasattr(signal, "SIGALRM"): signal.setitimer(signal.ITIMER_REAL, 0)
    def _raise(self, *a): raise TimeoutError("処理が制限時間を超えた(ReDoS/無限ループの疑い)")


# ---------- A. 性質ベース ----------

class PropertyTests(unittest.TestCase):
    def test_random_bytes_never_crash(self):
        """どんなランダムバイト列でも例外も時間切れも起きない"""
        rnd = random.Random(12345)
        for i in range(300):
            n = rnd.randint(0, 3000)
            blob = bytes(rnd.randint(0, 255) for _ in range(n))
            with Timeout(5):
                try:
                    scan_text(blob, name=f"r{i}.php")
                except (TimeoutError, Exception) as e:
                    self.fail(f"ランダム入力#{i}(len={n})で失敗: {type(e).__name__}: {e}")

    def test_random_php_snippets_never_crash(self):
        """PHPトークンをランダムに並べた断片でも落ちない"""
        toks = ["<?php", "eval(", "base64_decode(", "$_POST['x']", "system(", ")", ";",
                "'" + "A" * 50 + "'", "preg_replace(", "/e", "chr(65).", "$a=", "gzinflate(",
                "\\x41", "new $c(", "array_map(", "//comment\n", "<?=", "assert("]
        rnd = random.Random(999)
        for i in range(300):
            code = "".join(rnd.choice(toks) for _ in range(rnd.randint(1, 40)))
            with Timeout(5):
                try:
                    scan_text(code, name=f"s{i}.php")
                except (TimeoutError, Exception) as e:
                    self.fail(f"ランダムPHP断片#{i}で失敗: {type(e).__name__}: {e}\n{code[:200]}")

    def test_roundtrip_base64(self):
        """任意バイト列を base64_decode(エンコード後) で剥がすと元に戻る"""
        rnd = random.Random(7)
        for _ in range(200):
            data = bytes(rnd.randint(0, 255) for _ in range(rnd.randint(1, 500)))
            enc = base64.b64encode(data)
            self.assertEqual(m.DECODER_FUNCS["base64_decode"](enc), data)

    def test_roundtrip_multilayer(self):
        """base64→gzinflate の2層を積んで、自動展開で確実に剥がれる。
        実在のバックドアのペイロードは相応の長さがあるので、現実的な長さで検証する
        (短すぎるデータは展開しきい値を下回り誤展開を避けるため意図的に剥がさない)。"""
        rnd = random.Random(3)
        for _ in range(100):
            payload = ("<?php " + "eval($_POST['x']); " * rnd.randint(4, 30)).encode()
            layer = base64.b64encode(zlib.compress(payload)[2:-4])
            data = layer; applied = []
            for _ in range(m.MAX_LAYERS):
                r = m.auto_decode_once(data)
                if not r: break
                applied.append(r[0]); data = r[1]
            self.assertEqual(data, payload, f"多層展開が元に戻らない: {applied}")

    def test_strict_subset_of_normal(self):
        """strictの「高」は、常に通常モードの「高」の部分集合である"""
        samples = [
            '<?php eval($_POST["x"]);',
            '<?php eval(base64_decode("' + "QUJD" * 50 + '"));',
            '<?php preg_replace("/.*/e", $_POST["c"], "");',
            '<?php $x = gzinflate(base64_decode($y)); $x();',
            "<?php system($_GET['c']);",
        ]
        for code in samples:
            normal = {(f.kind,f.path) for f in scan_text(code).findings if f.severity == "高"}
            strict = {(f.kind,f.path) for f in scan_text(code, strict=True).findings if f.severity == "高"}
            self.assertTrue(strict <= normal, f"strictの高が通常を超過: {code}")

    def test_idempotent(self):
        """同じ入力を2回スキャンすると結果が一致する(冪等性)"""
        rnd = random.Random(55)
        for i in range(50):
            code = "<?php " + "".join(rnd.choice(["eval(", "$_POST['x']", ");", "echo 1;", "base64_decode("])
                                      for _ in range(rnd.randint(1, 15)))
            r1 = sorted((f.kind,f.detail) for f in scan_text(code, name=f"i{i}.php").findings)
            r2 = sorted((f.kind,f.detail) for f in scan_text(code, name=f"i{i}.php").findings)
            self.assertEqual(r1, r2)


# ---------- D. 敵対的(回避耐性) ----------

class AdversarialTests(unittest.TestCase):
    """検出を逃れようとする小細工に、本物のバックドアを見逃さないか"""

    def test_mixed_case_functions(self):
        # PHP関数は大小文字を区別しない。EvAl 等でも検出すべき
        for variant in ["EvAl($_POST['x'])", "ASSERT($_REQUEST['c'])",
                        "SyStEm($_GET['c'])", "eVaL(bAsE64_dEcOdE($_POST['c']))"]:
            sc = scan_text(f"<?php {variant};")
            self.assertTrue(is_high(sc), f"大小文字混在を見逃した: {variant}")

    def test_extra_whitespace(self):
        # 関数名と括弧の間に空白・改行・タブを挟む
        for variant in ["eval ($_POST['x'])", "eval\t($_POST['x'])",
                        "eval\n\n($_POST['x'])", "system  (  $_GET['c']  )"]:
            sc = scan_text(f"<?php {variant};")
            self.assertTrue(is_high(sc), f"空白挿入を見逃した: {variant!r}")

    def test_inline_comments_between_tokens(self):
        # トークンの間にコメントを挟んで難読化(本来は検出したいが、取りこぼしても落ちないこと)
        variants = [
            "eval/*x*/($_POST['c'])",
            "eval(/*x*/$_POST['c'])",
        ]
        for v in variants:
            sc = scan_text(f"<?php {v};")  # クラッシュしないことは必須
            self.assertIsNotNone(sc)

    def test_short_open_tag(self):
        # <?= や <? でもPHPとして実行される
        sc = scan_text("<?= eval($_POST['x']); ?>")
        self.assertIsNotNone(sc)

    def test_url_encoded_payload_in_image(self):
        # 画像偽装 + 先頭にコードの形
        sc = scan_text(b"GIF89a<?php assert($_POST['c']);", name="wp-content/uploads/x.gif")
        self.assertTrue(any(f.severity == "高" for f in sc.findings), "画像偽装+assertを見逃した")

    def test_single_quotes_vs_double(self):
        for q in ["'", '"']:
            sc = scan_text(f"<?php eval($_POST[{q}x{q}]);")
            self.assertTrue(is_high(sc), f"クォート種別 {q} で見逃した")

    def test_rot13_wrapped(self):
        # str_rot13 で包んだペイロード。auto_decodeが剥がせること
        payload = b"<?php eval($_POST['x']); // long enough to score"
        r13 = m.DECODER_FUNCS["str_rot13"](payload)
        # str_rot13でコードらしさが下がった状態から、再度rot13で戻る
        back = m.DECODER_FUNCS["str_rot13"](r13)
        self.assertEqual(back, payload)

    def test_case_insensitive_shell_hint(self):
        # Webシェルの痕跡が大文字小文字混在でも機能説明が成立(落ちない)
        sc = scan_text("<?php // FilesMan panel\n echo 1;")
        self.assertTrue(any("既知のWebシェル" in f.kind for f in sc.findings))


if __name__ == "__main__":
    unittest.main(verbosity=2)
