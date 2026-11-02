#!/usr/bin/env bash
# @desc:  ltrace / strace の定番オプションをモード指定で実行（ライブラリ呼び出し・比較関数・システムコール・ファイル・ネットワーク）
# @tags:  ctf, reversing, dynamic, ltrace, strace, trace, syscall, strcmp
# @deps:  ltrace, strace（Linux）
# @usage: echo 'AAAA' | bash reversing/dynamic/trace.sh cmp ./chall [args]
set -euo pipefail

usage() {
  cat >&2 <<USAGE
usage: $0 <mode> <binary> [args...]   （標準入力はそのままプログラムに渡る）
  cmp    比較・文字列系だけ ltrace（strcmp/strncmp/memcmp/strlen/strstr…）← まずこれ
  lib    全ライブラリ呼び出しを ltrace
  sys    全システムコールを strace
  file   ファイル関連の syscall（open/read/stat…）。設定ファイル・鍵ファイルの在処を探す
  net    ネットワーク関連の syscall（socket/connect/send…）
  exec   execve / fork / clone（子プロセス・自己再実行の把握）
  sig    シグナル（SIGTRAP / SIGSEGV を使うアンチデバッグの把握）
環境変数: OUT=log.txt でファイルに保存 / STRLEN=512 で文字列の表示長
USAGE
  exit 1
}
[[ $# -ge 2 ]] || usage
mode=$1
shift
len=${STRLEN:-256}
out=()
[[ -n ${OUT:-} ]] && out=(-o "$OUT")

need() { command -v "$1" >/dev/null || { echo "error: $1 が見つかりません (apt install $1)" >&2; exit 1; }; }

case $mode in
  cmp)
    need ltrace
    # -e で関数を絞る。@ 以降を指定しないと PLT 経由の呼び出しのみ（= 本体からの呼び出し）が対象
    exec ltrace -f -s "$len" "${out[@]}" \
      -e 'strcmp+strncmp+strcasecmp+strncasecmp+memcmp+bcmp+strstr+strlen+strcpy+strncpy+strcat+sprintf+snprintf+atoi+strtol+strtoul+puts+printf' \
      "$@"
    ;;
  lib)  need ltrace; exec ltrace -f -C -s "$len" "${out[@]}" "$@" ;;
  sys)  need strace; exec strace -f -s "$len" -yy "${out[@]}" "$@" ;;
  file) need strace; exec strace -f -s "$len" -yy -e trace=%file,read,write "${out[@]}" "$@" ;;
  net)  need strace; exec strace -f -s "$len" -yy -e trace=%network "${out[@]}" "$@" ;;
  exec) need strace; exec strace -f -s "$len" -e trace=%process "${out[@]}" "$@" ;;
  sig)  need strace; exec strace -f -e trace=none -e signal=all "${out[@]}" "$@" ;;
  *) usage ;;
esac
