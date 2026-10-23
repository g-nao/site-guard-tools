#!/usr/bin/env bash
# scan-all.sh の振る舞いテスト。 bash test_scan_all.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0; FAIL=0
ok()   { echo "  ok: $1"; PASS=$((PASS+1)); }
ng()   { echo "  NG: $1"; FAIL=$((FAIL+1)); }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/site-a" "$WORK/site-b" "$WORK/logs"

# モックスキャナー
cat > "$WORK/scanner.py" << 'PY'
import sys, argparse, os
ap=argparse.ArgumentParser(); ap.add_argument("root")
for o in ["--out","--wp-locale","--since","--baseline"]: ap.add_argument(o)
for o in ["--strict","--quiet","--all","--wp-core"]: ap.add_argument(o,action="store_true")
a=ap.parse_args()
rows=["高,uploads内のPHP,x.php,t,0,"] if a.root.endswith("site-a") else []
if a.root.endswith("site-a") and os.environ.get("INJECT_NEW"): rows.append("高,バックドア,n.php,i,0,")
open(a.out,"w",encoding="utf-8-sig").write("重要度,種別,ファイル,詳細,層,展開ファイル\n"+"".join(r+"\n" for r in rows))
if a.wp_core: print("本体照合: 10ファイル検証 / 改変 0 / 欠落 0 / 見知らぬPHP 0")
print(f"重要度 高: {len(rows)} 件"); print("重要度 中: 0 件")
PY

run() { SCANNER="$WORK/scanner.py" SCAN_CONF="$WORK/sites.conf" SCAN_OUTDIR="$WORK/logs" USE_SUDO=0 bash "$HERE/scan-all.sh" "$@" 2>&1; }

# --- 1: 設定ファイルが無いとエラー(exit 2) ---
rm -f "$WORK/sites.conf"
run >/dev/null 2>&1; [ $? -eq 2 ] && ok "設定ファイル無しでexit 2" || ng "設定ファイル無しでexit 2"

# --- 2: 通常実行で両サイトを処理 ---
printf 'sitea|wp|ja|%s/site-a\nsiteb|static|-|%s/site-b\n' "$WORK" "$WORK" > "$WORK/sites.conf"
out="$(run)"
echo "$out" | grep -q "\[sitea\]" && echo "$out" | grep -q "\[siteb\]" && ok "両サイト処理" || ng "両サイト処理"

# --- 3: コメント行・空行を無視 ---
printf '# これはコメント\n\nsitea|wp|ja|%s/site-a\n' "$WORK" > "$WORK/sites.conf"
out="$(run)"
echo "$out" | grep -q "\[sitea\]" && ! echo "$out" | grep -q "これはコメント" && ok "コメント・空行を無視" || ng "コメント・空行を無視"

# --- 4: --site で絞り込み ---
printf 'sitea|wp|ja|%s/site-a\nsiteb|static|-|%s/site-b\n' "$WORK" "$WORK" > "$WORK/sites.conf"
out="$(run --site siteb)"
echo "$out" | grep -q "\[siteb\]" && ! echo "$out" | grep -q "\[sitea\]" && ok "--site 絞り込み" || ng "--site 絞り込み"

# --- 5: 存在しないパスはスキップ(落ちない) ---
printf 'gone|static|-|%s/nonexist\n' "$WORK" > "$WORK/sites.conf"
out="$(run)"; echo "$out" | grep -q "パスが存在しません" && ok "存在しないパスをスキップ" || ng "存在しないパスをスキップ"

# --- 6: cron差分で新規「高」を検知しexit 1 ---
printf 'sitea|wp|ja|%s/site-a\n' "$WORK" > "$WORK/sites.conf"
run >/dev/null 2>&1                    # 1回目(baseline作成)
INJECT_NEW=1 run --cron >/dev/null 2>&1; [ $? -eq 1 ] && ok "cron新規検知でexit 1" || ng "cron新規検知でexit 1"

# --- 7: cron差分で変化なしならexit 0 ---
INJECT_NEW=1 run --cron >/dev/null 2>&1; [ $? -eq 0 ] && ok "cron変化なしでexit 0" || ng "cron変化なしでexit 0"

# --- 8: CRLF改行の設定ファイルでも読める ---
printf 'sitea|wp|ja|%s/site-a\r\n' "$WORK" > "$WORK/sites.conf"
out="$(run)"; echo "$out" | grep -q "\[sitea\]" && ok "CRLF改行を許容" || ng "CRLF改行を許容"


# --- 9: サイトごとのallowlistがあればスキャナーに --allowlist で渡す ---
printf 'sitea|wp|ja|%s/site-a\n' "$WORK" > "$WORK/sites.conf"
echo "dummyhash  x.php" > "$WORK/logs/allowlist-sitea.txt"
# モックスキャナーを、--allowlist を受け取ったら印をログに残す版に差し替え
cat > "$WORK/scanner.py" << 'PY'
import sys, argparse, os
ap=argparse.ArgumentParser(); ap.add_argument("root")
for o in ["--out","--wp-locale","--since","--baseline","--allowlist"]: ap.add_argument(o)
for o in ["--strict","--quiet","--all","--wp-core"]: ap.add_argument(o,action="store_true")
a=ap.parse_args()
open(a.out,"w",encoding="utf-8-sig").write("重要度,種別,ファイル,詳細,層,展開ファイル\n")
if a.allowlist: open(os.path.join(os.path.dirname(a.out),"got-allowlist.txt"),"w").write(a.allowlist)
print("重要度 高: 0 件"); print("重要度 中: 0 件")
PY
run >/dev/null 2>&1
[ -f "$WORK/logs/got-allowlist.txt" ] && grep -q "allowlist-sitea.txt" "$WORK/logs/got-allowlist.txt" && ok "サイトごとallowlistを渡す" || ng "サイトごとallowlistを渡す"

# --- 10: allowlistが無いサイトは --allowlist を渡さない(エラーにしない) ---
rm -f "$WORK/logs/allowlist-sitea.txt" "$WORK/logs/got-allowlist.txt"
run >/dev/null 2>&1
[ ! -f "$WORK/logs/got-allowlist.txt" ] && ok "allowlist無しでも正常動作" || ng "allowlist無しでも正常動作"

echo ""
echo "結果: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
