#!/usr/bin/env bash
# @desc:  全 TCP/UDP ストリームを個別ファイルにダンプ（Follow TCP Stream の一括版）
# @tags:  ctf, network, pcap, tcp, udp, stream, follow, tshark
# @deps:  tshark
# @usage: bash network/pcap/follow_tcp.sh capture.pcap ./streams [tcp|udp] [ascii|raw]
set -euo pipefail

[[ $# -ge 1 ]] || { echo "usage: $0 <pcap> [outdir=./streams] [tcp|udp] [ascii|raw]" >&2; exit 1; }
command -v tshark >/dev/null || { echo "error: tshark が見つかりません" >&2; exit 1; }
pcap=$1
outdir=${2:-./streams}
proto=${3:-tcp}
fmt=${4:-ascii}   # raw = hex 出力（バイナリを xxd -r -p で復元可能）
mkdir -p "$outdir"

streams=$(tshark -r "$pcap" -T fields -e "$proto.stream" -Y "$proto" | sort -un)
count=0
for s in $streams; do
  tshark -r "$pcap" -q -z "follow,$proto,$fmt,$s" > "$outdir/${proto}_stream_$s.txt"
  count=$((count + 1))
done
echo "[+] $count streams -> $outdir"
echo "    サイズ順: ls -S $outdir | head"
echo "    flag 検索: grep -ail 'flag{' $outdir/*"
