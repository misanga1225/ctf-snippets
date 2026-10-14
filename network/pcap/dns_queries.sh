#!/usr/bin/env bash
# @desc:  DNS クエリ名・レコード種別・応答を一覧化（ユニーク/出現回数順）
# @tags:  ctf, soc, network, pcap, dns, tshark
# @deps:  tshark
# @usage: bash network/pcap/dns_queries.sh capture.pcap [--answers]
set -euo pipefail

[[ $# -ge 1 ]] || { echo "usage: $0 <pcap> [--answers]" >&2; exit 1; }
command -v tshark >/dev/null || { echo "error: tshark が見つかりません" >&2; exit 1; }
pcap=$1

if [[ ${2:-} == "--answers" ]]; then
  # クエリ名と応答（A/AAAA/CNAME/TXT）を並べて表示
  tshark -r "$pcap" -Y "dns.flags.response == 1" -T fields -E separator=$'\t' \
    -e dns.qry.name -e dns.a -e dns.aaaa -e dns.cname -e dns.txt | sort -u
else
  echo "count  type  name"
  tshark -r "$pcap" -Y "dns.flags.response == 0" -T fields -e dns.qry.type -e dns.qry.name \
    | sort | uniq -c | sort -rn
fi
