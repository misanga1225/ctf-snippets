#!/usr/bin/env bash
# @desc:  pcap の全体像を把握（プロトコル階層・IP 会話・TCP 会話・HTTP ホスト・DNS 統計）
# @tags:  ctf, network, pcap, tshark, overview, statistics
# @deps:  tshark
# @usage: bash network/pcap/pcap_summary.sh capture.pcap
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 <pcap>" >&2; exit 1; }
command -v tshark >/dev/null || { echo "error: tshark が見つかりません (brew install wireshark / apt install tshark)" >&2; exit 1; }
pcap=$1

section() { printf '\n\033[1;36m===== %s =====\033[0m\n' "$1"; }

section "capinfos"
capinfos -c -d -u -a -e "$pcap" 2>/dev/null || true
section "Protocol Hierarchy"
tshark -r "$pcap" -q -z io,phs
section "IPv4 Conversations"
tshark -r "$pcap" -q -z conv,ip | head -30
section "TCP Conversations"
tshark -r "$pcap" -q -z conv,tcp | head -30
section "HTTP Hosts / Requests"
tshark -r "$pcap" -Y http.request -T fields -e ip.src -e http.request.method -e http.host -e http.request.uri \
  | sort | uniq -c | sort -rn | head -30
section "DNS Queries (top)"
tshark -r "$pcap" -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -30
section "flag っぽい平文文字列（pcap を直接 grep。分割/圧縮/暗号化されたものは拾えない）"
grep -aoiE '[a-z0-9_]{2,}\{[^}[:space:]]{3,}\}' "$pcap" | sort -u | head -20 || true
