#!/usr/bin/env bash
# @desc:  objdump ラッパー（Intel 記法で関数/アドレス範囲を逆アセンブル、関数一覧、stripped バイナリの main 特定）
# @tags:  ctf, reversing, static, objdump, disassemble, intel, stripped, main
# @deps:  objdump（GNU binutils または llvm-objdump）, nm
# @usage: bash reversing/static/disasm.sh ./chall [main|0x401136|--list|--entry|--all] [len=0x100]
set -euo pipefail

usage() {
  cat >&2 <<USAGE
usage: $0 <binary> [target] [len]
  main / check など   その関数を逆アセンブル（シンボルが必要）
  0x401136            そのアドレスから len バイト（default 0x100）
  --list              関数シンボル一覧（アドレス順）
  --entry             エントリポイント付近を表示し main のアドレスを推定（stripped 向け）
  --all               .text 全体
環境変数: OBJDUMP=llvm-objdump などで objdump を差し替え / RAW=1 で機械語バイトも表示
USAGE
  exit 1
}
[[ $# -ge 1 ]] || usage
bin=$1
target=${2:-main}
len=${3:-0x100}
[[ -f $bin ]] || { echo "error: $bin が見つかりません" >&2; exit 1; }

# brew の binutils は gobjdump という名前で入る（macOS 標準の objdump は llvm 版）
if [[ -z ${OBJDUMP:-} ]]; then
  for c in gobjdump objdump llvm-objdump; do command -v "$c" >/dev/null && { OBJDUMP=$c; break; }; done
fi
[[ -n ${OBJDUMP:-} ]] || { echo "error: objdump が見つかりません (apt install binutils / brew install binutils)" >&2; exit 1; }
NM=nm
command -v gnm >/dev/null && NM=gnm
gnu=false
"$OBJDUMP" --version 2>/dev/null | head -1 | grep -q GNU && gnu=true

opts=(-d -C)
[[ ${RAW:-0} == 1 ]] || opts+=(--no-show-raw-insn)
if file -b "$bin" | grep -qE 'x86-64|80386|Intel|x86'; then
  opts+=(-M intel)
  if $gnu && ! "$OBJDUMP" -i 2>/dev/null | grep -q 'x86-64'; then
    echo "error: この objdump は x86 を扱えません。x86_64-linux-gnu-objdump / binutils-multiarch / llvm-objdump を OBJDUMP= で指定" >&2
    exit 1
  fi
elif $gnu && ! "$OBJDUMP" -i 2>/dev/null | grep -qiE 'aarch64|arm'; then
  echo "note: この GNU objdump は x86 専用の可能性。他アーキは binutils-multiarch か llvm-objdump を使う" >&2
fi
$gnu && opts+=(-w)

case $target in
  --list)
    if ! "$NM" -C --defined-only "$bin" 2>/dev/null | grep -E ' [tTwW] ' | sort; then
      echo "関数シンボルがありません（stripped）→ '$0 $bin --entry' で main を推定するか Ghidra / r2 で解析" >&2
    fi
    ;;
  --all)
    "$OBJDUMP" "${opts[@]}" -j .text "$bin"
    ;;
  --entry)
    entry=$("$OBJDUMP" -f "$bin" | awk '/start address/ {print $NF}')
    echo "entry point: $entry"
    out=$("$OBJDUMP" "${opts[@]}" --start-address="$entry" --stop-address=$((entry + 0x40)) "$bin")
    echo "$out" | sed -n '/>:$/,$p'
    # x86-64 glibc: _start は main のアドレスを rdi に入れて __libc_start_main を呼ぶ
    # 最初の call より前で rdi/edi に入れているアドレス（"# 1294" 注釈 or "mov edi,0x401281" の即値）を拾う
    main=$(echo "$out" | sed -n '/>:$/,$p' | awk '
      /[[:space:]]call/ { exit }
      /(rdi|edi), ?/ {
        if (match($0, /# *(0x)?[0-9a-f]+/)) { s = substr($0, RSTART, RLENGTH); gsub(/[# ]|0x/, "", s); m = "0x" s }
        else if (match($0, /, *0x[0-9a-f]+/)) { s = substr($0, RSTART, RLENGTH); gsub(/[, ]/, "", s); m = s }
      }
      END { print m }')
    if [[ -n $main ]]; then
      echo
      echo "[+] main は $main の可能性（__libc_start_main の第 1 引数）→ $0 $bin $main"
    else
      echo
      echo "x86 以外 / 非 glibc では自動推定できません。__libc_start_main 呼び出し直前の第 1 引数レジスタ（x0 / r0 / a0）を見る"
    fi
    ;;
  0x*|[0-9]*)
    "$OBJDUMP" "${opts[@]}" --start-address="$target" --stop-address=$((target + len)) "$bin" | sed -n '/>:$/,$p'
    ;;
  -*)
    usage
    ;;
  *)
    if $gnu; then
      out=$("$OBJDUMP" "${opts[@]}" --disassemble="$target" "$bin")
    else
      out=$("$OBJDUMP" "${opts[@]}" --disassemble-symbols="$target" "$bin" 2>/dev/null || true)
    fi
    if ! echo "$out" | grep -q '>:$'; then
      echo "シンボル '$target' が見つかりません。'$0 $bin --list' で一覧を確認（stripped なら --entry / アドレス指定）" >&2
      exit 1
    fi
    echo "$out" | sed -n '/>:$/,$p'
    ;;
esac
