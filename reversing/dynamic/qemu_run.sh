#!/usr/bin/env bash
# @desc:  ARM/AArch64/MIPS/RISC-V/PowerPC/x86 など他アーキの Linux ELF を qemu-user で実行（アーキ自動判定・sysroot 自動選択・gdb 接続待ち）
# @tags:  ctf, reversing, dynamic, qemu, arm, aarch64, mips, riscv, cross, gdb-multiarch
# @deps:  qemu-user（apt install qemu-user / qemu-user-static）、動的リンクなら libc6-<arch>-cross
# @usage: bash reversing/dynamic/qemu_run.sh ./chall_arm [args]   /   GDB=1234 bash reversing/dynamic/qemu_run.sh ./chall_arm
set -euo pipefail

usage() {
  cat >&2 <<USAGE
usage: [GDB=<port>] [SYSROOT=<dir>] $0 <elf> [args...]
  GDB=1234     gdb の接続を待って停止（別端末で表示される gdb-multiarch コマンドを実行）
  SYSROOT=dir  動的リンクの libc を探すディレクトリ（既定: /usr/<triple> を自動選択）
  STRACE=1     qemu の -strace（システムコールログ）を有効化
USAGE
  exit 1
}
[[ $# -ge 1 ]] || usage
bin=$1
shift
[[ -f $bin ]] || { echo "error: $bin が見つかりません" >&2; exit 1; }
[[ $(od -An -tx1 -N4 "$bin" | tr -d ' \n') == 7f454c46 ]] || { echo "error: ELF ではありません" >&2; exit 1; }

# ELF ヘッダから class / endian / e_machine を読む
cls=$(od -An -tu1 -j4 -N1 "$bin" | tr -d ' ')
endian=$(od -An -tu1 -j5 -N1 "$bin" | tr -d ' ')
if [[ $endian == 1 ]]; then
  machine=$(od -An -tu1 -j18 -N2 "$bin" | awk '{print $1 + $2 * 256}')
else
  machine=$(od -An -tu1 -j18 -N2 "$bin" | awk '{print $1 * 256 + $2}')
fi

# e_machine → qemu のアーキ名と Debian のクロス sysroot
case "$machine:$cls:$endian" in
  62:2:1)  q=x86_64;  triples="x86_64-linux-gnu" ;;
  3:1:1)   q=i386;    triples="i686-linux-gnu i386-linux-gnu" ;;
  183:2:1) q=aarch64; triples="aarch64-linux-gnu" ;;
  40:1:1)  q=arm;     triples="arm-linux-gnueabihf arm-linux-gnueabi" ;;
  40:1:2)  q=armeb;   triples="armeb-linux-gnueabi" ;;
  8:1:2)   q=mips;    triples="mips-linux-gnu" ;;
  8:1:1)   q=mipsel;  triples="mipsel-linux-gnu" ;;
  8:2:2)   q=mips64;  triples="mips64-linux-gnuabi64" ;;
  8:2:1)   q=mips64el; triples="mips64el-linux-gnuabi64" ;;
  20:1:2)  q=ppc;     triples="powerpc-linux-gnu" ;;
  21:2:2)  q=ppc64;   triples="powerpc64-linux-gnu" ;;
  21:2:1)  q=ppc64le; triples="powerpc64le-linux-gnu" ;;
  243:2:1) q=riscv64; triples="riscv64-linux-gnu" ;;
  22:2:2)  q=s390x;   triples="s390x-linux-gnu" ;;
  *) echo "error: 未対応の e_machine=$machine class=$cls endian=$endian" >&2; exit 1 ;;
esac

qemu=""
for c in "qemu-$q" "qemu-$q-static"; do command -v "$c" >/dev/null && { qemu=$c; break; }; done
[[ -n $qemu ]] || { echo "error: qemu-$q が見つかりません (apt install qemu-user)" >&2; exit 1; }

opts=()
sysroot=${SYSROOT:-}
if [[ -z $sysroot ]] && LC_ALL=C grep -aq 'ld-linux\|ld\.so' "$bin"; then  # 動的リンク
  for t in $triples; do [[ -d /usr/$t ]] && { sysroot=/usr/$t; break; }; done
  [[ -n $sysroot ]] || echo "warning: sysroot が見つかりません。apt install libc6-${triples%%-*}-cross 等を入れるか SYSROOT= を指定" >&2
fi
[[ -n $sysroot ]] && opts+=(-L "$sysroot")
[[ ${STRACE:-0} == 1 ]] && opts+=(-strace)

if [[ -n ${GDB:-} ]]; then
  opts+=(-g "$GDB")
  cat >&2 <<EOF
[*] gdb の接続待ち (port $GDB)。別の端末で:
    gdb-multiarch -q $bin \\
      ${sysroot:+-ex 'set sysroot $sysroot'} \\
      -ex 'target remote :$GDB' -ex 'b main' -ex 'c'
EOF
fi
echo "[*] $qemu ${opts[*]} $bin $*" >&2
exec "$qemu" "${opts[@]}" "$bin" "$@"
