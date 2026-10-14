#!/usr/bin/env bash
# @desc:  HTTP リクエスト一覧を表示し、転送ファイル（HTTP/SMB/FTP-DATA 等のオブジェクト）を抽出
# @tags:  ctf, network, pcap, http, export-objects, tshark, file-carving
# @deps:  tshark
# @usage: bash network/pcap/extract_http.sh capture.pcap ./out
set -euo pipefail

[[ $# -ge 1 ]] || { echo "usage: $0 <pcap> [outdir=./out]" >&2; exit 1; }
command -v tshark >/dev/null || { echo "error: tshark が見つかりません" >&2; exit 1; }
# tshark 4.x は http.file_data を hex で出力するため、hex なら復号して表示
unhex() { if [[ $1 =~ ^([0-9a-fA-F]{2})+$ ]]; then printf '%s' "$1" | xxd -r -p; else printf '%s' "$1"; fi; }
pcap=$1
outdir=${2:-./out}

echo "## HTTP requests (frame, src, method, host, uri, user-agent)"
tshark -r "$pcap" -Y http.request -T fields -E separator=$'\t' \
  -e frame.number -e ip.src -e http.request.method -e http.host -e http.request.uri -e http.user_agent

echo
echo "## HTTP POST bodies"
tshark -r "$pcap" -Y 'http.request.method == "POST"' -T fields -E separator=$'\t' \
  -e http.host -e http.request.uri -e http.file_data \
  | while IFS=$'\t' read -r host uri body; do printf '%s%s\t%s\n' "$host" "$uri" "$(unhex "$body")"; done

for proto in http smb tftp imf ftp-data; do
  dir="$outdir/$proto"
  mkdir -p "$dir"
  tshark -r "$pcap" -q --export-objects "$proto,$dir" >/dev/null 2>&1 || true
  if [[ -n $(ls -A "$dir") ]]; then
    echo
    echo "## exported $proto objects -> $dir"
    (cd "$dir" && file -- * | head -50)
  else
    rmdir "$dir"
  fi
done
