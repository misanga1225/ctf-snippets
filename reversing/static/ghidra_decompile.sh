#!/usr/bin/env bash
# @desc:  Ghidra をヘッドレス実行して全関数（または指定関数）を C 言語に逆コンパイルしファイル出力（GUI 不要）
# @tags:  ctf, reversing, static, ghidra, decompile, headless
# @deps:  Ghidra（analyzeHeadless）, Java 17+
# @usage: bash reversing/static/ghidra_decompile.sh ./chall [out.c] [関数名フィルタ]
set -euo pipefail

[[ $# -ge 1 ]] || { echo "usage: $0 <binary> [out.c=<binary>.c] [function-filter]" >&2; exit 1; }
bin=$1
[[ -f $bin ]] || { echo "error: $bin が見つかりません" >&2; exit 1; }
out=${2:-$(basename "$bin").c}
filter=${3:-}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# analyzeHeadless を探す: $GHIDRA_HOME → PATH → Homebrew → よくある展開先
find_headless() {
  local c
  for c in "${GHIDRA_HOME:-}/support/analyzeHeadless" "$(command -v analyzeHeadless 2>/dev/null || true)" \
           /opt/homebrew/Cellar/ghidra/*/libexec/support/analyzeHeadless \
           /usr/local/Cellar/ghidra/*/libexec/support/analyzeHeadless \
           /opt/ghidra*/support/analyzeHeadless "$HOME"/ghidra*/support/analyzeHeadless; do
    [[ -n $c && -x $c ]] && { echo "$c"; return; }
  done
}
headless=$(find_headless)
[[ -n $headless ]] || { echo "error: analyzeHeadless が見つかりません。GHIDRA_HOME=<ghidra の展開先> を設定してください" >&2; exit 1; }
# Homebrew 版は JAVA_HOME を ghidraRun ラッパーで設定しているので合わせる
if [[ -z ${JAVA_HOME:-} && -d /opt/homebrew/opt/openjdk/libexec/openjdk.jdk ]]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home
fi
for v in /opt/homebrew/opt/openjdk@*/libexec/openjdk.jdk/Contents/Home; do
  [[ -z ${JAVA_HOME:-} && -d $v ]] && export JAVA_HOME=$v
done

abs() { (cd "$(dirname "$1")" && echo "$(pwd)/$(basename "$1")"); }
bin_abs=$(abs "$bin")
out_abs=$(abs "$out")
proj=$(mktemp -d)
trap 'rm -rf "$proj"' EXIT

echo "[*] Ghidra 解析中（大きいバイナリは数分かかります）: $headless"
if ! "$headless" "$proj" ctf -import "$bin_abs" -scriptPath "$here" \
     -postScript DecompileAll.java "$out_abs" "$filter" -deleteProject > "$proj/headless.log" 2>&1 \
   || ! grep -q 'DecompileAll:' "$proj/headless.log"; then
  echo "error: Ghidra の実行に失敗しました。ログ末尾:" >&2
  tail -30 "$proj/headless.log" >&2
  exit 1
fi
grep -o 'DecompileAll:.*' "$proj/headless.log" | sed 's/ (GhidraScript).*//'
echo "[+] $out"
echo "    次: grep -n 'main\\|check\\|flag' '$out'  /  less '$out'"
