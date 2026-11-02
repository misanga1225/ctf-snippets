#!/usr/bin/env bash
# @desc:  radare2 を非対話で実行して定番の解析結果を出す（情報・関数一覧・main 逆アセ/疑似 C・文字列・文字列の参照元・呼び出し関係）
# @tags:  ctf, reversing, static, radare2, r2, rizin, xref, disassemble, decompile
# @deps:  radare2（R2=rizin で rizin も可。dec は r2ghidra / r2dec があれば使う）
# @usage: bash reversing/static/r2_analyze.sh ./chall [info|funcs|main|func <名前|0xaddr>|dec <名前>|strings|xref <文字列>|calls <名前>]
set -euo pipefail

usage() {
  cat >&2 <<USAGE
usage: $0 <binary> [mode] [arg]
  info              バイナリ情報・セキュリティ機構・エントリ・インポート
  funcs   (default) 関数一覧（aaa 解析後。サイズ順で大きい自作関数を探しやすい）
  main              main を逆アセンブル
  func <名前|addr>  指定関数を逆アセンブル（例: sym.check / 0x401196）
  dec  <名前|addr>  疑似 C（r2ghidra の pdg → r2dec の pdd → 内蔵 pdc の順に試す）
  strings           データセクションの文字列（アドレス付き）
  xref <文字列>     その文字列を参照している命令・関数（"Correct" の参照元 = 判定箇所）
  calls <名前|addr> その関数が呼んでいる関数一覧
USAGE
  exit 1
}
[[ $# -ge 1 ]] || usage
bin=$1
mode=${2:-funcs}
arg=${3:-}
R2=${R2:-r2}
command -v "$R2" >/dev/null || { echo "error: $R2 が見つかりません (brew install radare2 / https://github.com/radareorg/radare2/releases)" >&2; exit 1; }
[[ -f $bin ]] || { echo "error: $bin が見つかりません" >&2; exit 1; }

r2c() { "$R2" -q -e scr.color=0 -e bin.relocs.apply=true -e asm.bytes=false -c "$1" "$bin" 2>/dev/null; }
need_arg() { [[ -n $arg ]] || { echo "error: $mode には引数が必要です" >&2; usage; }; }

case $mode in
  info)    r2c 'iI; echo; echo [entry]; ie; echo; echo [imports]; ii' ;;
  funcs)   r2c 'aaa; afl,size/sort/dec' ;;
  main)    r2c 'aaa; s main; pdf' ;;
  func)    need_arg; r2c "aaa; s $arg; pdf" ;;
  dec)
    need_arg
    if r2c 'Lc' | grep -q 'r2ghidra'; then r2c "aaa; s $arg; pdg"
    elif r2c 'Lc' | grep -qi 'r2dec'; then r2c "aaa; s $arg; pdd"
    else echo "(r2ghidra / r2dec 未導入のため内蔵 pdc。r2pm -ci r2ghidra で導入可)" >&2; r2c "aaa; s $arg; pdc"
    fi
    ;;
  strings) r2c 'iz' ;;
  xref)
    need_arg
    addrs=$(r2c 'iz' | awk -v pat="$arg" 'index($0, pat) && $3 ~ /^0x/ {print $3}')
    [[ -n $addrs ]] || { echo "文字列 '$arg' が見つかりません（$0 $bin strings で確認）" >&2; exit 1; }
    for a in $addrs; do
      echo "## $(r2c "ps @ $a") @ $a"
      r2c "aaa; axt @ $a"
    done
    ;;
  calls)   need_arg; r2c "aaa; s $arg; afx" ;;
  *) usage ;;
esac
