#!/usr/bin/env bash
#
# scan-all.sh - 複数サイトをまとめてマルウェア点検するラッパー
#
# 使い方:
#   ./scan-all.sh              通常実行(全サイトをスキャンし、結果を画面表示)
#   ./scan-all.sh --cron       定期実行用(前回との差分=新しく増えた「高」だけを通知)
#   ./scan-all.sh --site KEY   特定サイトだけスキャン(sites.conf のキー名)
#
# 前提:
#   - 同じディレクトリに php_malware_scan.py がある(または SCANNER 環境変数で指定)
#   - sites.conf にスキャン対象を定義(sites.conf.example をコピーして作る)
#   - Dockerボリューム等を読むのに sudo が要る場合は、下記 USE_SUDO=1 のまま
#   - Python 3.9 以上
#
# cron登録例(毎週月曜 4:55、新規検出があればログに残す):
#   55 4 * * 1 /path/to/scan-all.sh --cron >> /path/to/scan-logs/cron.log 2>&1

set -uo pipefail

# ---- 設定(環境変数で上書き可) ----
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER="${SCANNER:-$HERE/php_malware_scan.py}"
CONF="${SCAN_CONF:-$HERE/sites.conf}"
OUTDIR="${SCAN_OUTDIR:-$HOME/scan-logs}"
PY="${PYTHON:-python3}"
USE_SUDO="${USE_SUDO:-1}"      # root専用ディレクトリを読むなら 1。不要なら 0

sudo_cmd() { if [ "$USE_SUDO" = "1" ]; then sudo "$@"; else "$@"; fi; }

# ---- 引数 ----
MODE="normal"
ONLY_SITE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --cron) MODE="cron" ;;
    --site) ONLY_SITE="${2:-}"; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "不明な引数: $1" >&2; exit 2 ;;
  esac
  shift
done

# ---- 前提チェック ----
if [ ! -f "$SCANNER" ]; then
  echo "エラー: スキャナーが見つかりません: $SCANNER" >&2
  exit 2
fi
if [ ! -f "$CONF" ]; then
  echo "エラー: 設定ファイルがありません: $CONF" >&2
  echo "  sites.conf.example をコピーして sites.conf を作ってください:" >&2
  echo "    cp '$HERE/sites.conf.example' '$CONF'" >&2
  exit 2
fi

# ---- サイト定義を読み込む ----
# 形式(1行1サイト): キー|種別(wp/static)|ロケール|パス  (# で始まる行と空行は無視)
SITES=()
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%%$'\r'}"                       # 末尾CRを除去(Windows改行対策)
  case "$line" in ''|\#*) continue ;; esac    # 空行・コメント行はスキップ
  SITES+=("$line")
done < "$CONF"

if [ "${#SITES[@]}" -eq 0 ]; then
  echo "エラー: $CONF に有効なサイト定義がありません" >&2
  exit 2
fi

mkdir -p "$OUTDIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
TODAY="$(date '+%Y-%m-%d %H:%M')"
SUMMARY="$OUTDIR/summary-$STAMP.txt"
NEWHITS="$OUTDIR/new-high-$STAMP.txt"
: > "$NEWHITS"

echo "===== 全サイト点検 $TODAY =====" | tee "$SUMMARY"

total_new=0
for entry in "${SITES[@]}"; do
  IFS='|' read -r key kind locale path <<< "$entry"
  [ -n "$ONLY_SITE" ] && [ "$ONLY_SITE" != "$key" ] && continue

  echo "" | tee -a "$SUMMARY"
  echo "--- [$key] $path ---" | tee -a "$SUMMARY"
  if ! sudo_cmd test -e "$path"; then
    echo "  パスが存在しません(スキップ)" | tee -a "$SUMMARY"
    continue
  fi

  out="$OUTDIR/$key-latest.csv"
  prev="$OUTDIR/$key-prev.csv"
  [ -f "$out" ] && cp "$out" "$prev"

  opts=(--out "$out" --strict --quiet)
  if [ "$kind" = "wp" ]; then
    opts+=(--wp-core --wp-locale "$locale")
  else
    opts+=(--all)
  fi
  if [ "$MODE" = "cron" ] && [ -f "$prev" ]; then
    opts+=(--baseline "$prev")
  fi
  # サイトごとの確認済み正規ファイル除外リスト(あれば渡す)。無ければ従来どおり。
  allow="$OUTDIR/allowlist-$key.txt"
  if [ -f "$allow" ]; then
    opts+=(--allowlist "$allow")
  fi

  result="$(sudo_cmd "$PY" "$SCANNER" "$path" "${opts[@]}" 2>&1)"
  echo "$result" | grep -E "本体照合:|重要度 (高|中):" | sed 's/^/  /' | tee -a "$SUMMARY"

  if [ -f "$out" ]; then
    high_now="$(grep -c '^高,' "$out" 2>/dev/null | tr -d '\n')"; high_now="${high_now:-0}"
    if [ "$MODE" = "cron" ] && [ -f "$prev" ]; then
      new_high="$(comm -13 <(grep '^高,' "$prev" 2>/dev/null | sort) <(grep '^高,' "$out" 2>/dev/null | sort))"
      if [ -n "$new_high" ]; then
        cnt="$(echo "$new_high" | grep -c '^高,')"
        total_new=$((total_new + cnt))
        echo "  ★新しく増えた「高」: $cnt 件" | tee -a "$SUMMARY"
        { echo "[$key] 新規の高 $cnt 件:"; echo "$new_high"; echo ""; } >> "$NEWHITS"
      else
        echo "  前回からの新規「高」なし(現在 $high_now 件)" | tee -a "$SUMMARY"
      fi
    else
      echo "  高 $high_now 件(詳細: $out)" | tee -a "$SUMMARY"
    fi
  fi
done

echo "" | tee -a "$SUMMARY"
echo "===== 完了 =====" | tee -a "$SUMMARY"
echo "サマリ: $SUMMARY" | tee -a "$SUMMARY"

if [ "$MODE" = "cron" ]; then
  if [ "$total_new" -gt 0 ]; then
    { echo ""; echo "⚠ 新しく増えた「高」が合計 $total_new 件あります: $NEWHITS"; } | tee -a "$SUMMARY"
    # メール通知を使う場合は以下のコメントを外す(mailコマンドが必要)
    # mail -s "[scan-all] 新規検出 $total_new 件" you@example.com < "$NEWHITS"
    exit 1
  fi
  rm -f "$NEWHITS"
  echo "新規検出なし。問題ありません。" | tee -a "$SUMMARY"
  exit 0
fi
exit 0
