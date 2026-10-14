#!/usr/bin/env bash
# @desc:  平文認証情報の抽出（FTP/Telnet/HTTP Basic/HTTP POST/POP/IMAP/SMTP AUTH/NTLM）
# @tags:  ctf, soc, network, pcap, credentials, password, ftp, telnet, http, tshark
# @deps:  tshark
# @usage: bash network/pcap/creds_sniff.sh capture.pcap
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 <pcap>" >&2; exit 1; }
command -v tshark >/dev/null || { echo "error: tshark が見つかりません" >&2; exit 1; }
pcap=$1

# tshark 4.x は http.file_data を hex で出力するため、hex なら復号して表示
unhex() { if [[ $1 =~ ^([0-9a-fA-F]{2})+$ ]]; then printf '%s' "$1" | xxd -r -p; else printf '%s' "$1"; fi; }
section() { printf '\n\033[1;33m## %s\033[0m\n' "$1"; }

section "Wireshark credentials tap (FTP/HTTP/POP/IMAP/SMTP 等)"
tshark -r "$pcap" -q -z credentials 2>/dev/null || echo "(この tshark では -z credentials 非対応)"

section "FTP USER/PASS"
tshark -r "$pcap" -Y 'ftp.request.command == "USER" || ftp.request.command == "PASS"' -T fields \
  -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg

section "HTTP Basic Auth"
tshark -r "$pcap" -Y http.authbasic -T fields -e ip.src -e http.host -e http.authbasic

section "HTTP POST (login/password を含むもの)"
tshark -r "$pcap" -Y 'http.request.method == "POST"' -T fields -E separator=$'\t' \
  -e ip.src -e http.host -e http.request.uri -e http.file_data \
  | while IFS=$'\t' read -r src host uri body; do
      printf '%s\t%s%s\t%s\n' "$src" "$host" "$uri" "$(unhex "$body")"
    done | grep -aiE 'pass|pwd|login|user' || true

section "POP/IMAP/SMTP コマンド"
tshark -r "$pcap" -Y 'pop.request or imap.request or smtp.req.command == "AUTH"' -T fields \
  -e ip.src -e pop.request -e imap.request -e smtp.req.parameter

section "Telnet データ（1 文字ずつ送られるため結合して表示）"
tshark -r "$pcap" -Y telnet.data -T fields -e tcp.stream -e telnet.data 2>/dev/null \
  | awk -F'\t' '{a[$1]=a[$1] $2} END {for (s in a) print "stream " s ": " a[s]}' || true

section "NTLM (hashcat -m 5600 用の材料)"
tshark -r "$pcap" -Y ntlmssp.messagetype==3 -T fields \
  -e ntlmssp.auth.domain -e ntlmssp.auth.username -e ntlmssp.ntlmv2_response.ntproofstr 2>/dev/null || true
