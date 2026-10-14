#!/usr/bin/env bash
# @desc:  nmap の定番スキャンプリセット（全ポート高速発見 → 開いたポートだけ詳細スキャン）
# @tags:  ctf, noc, nmap, scan, recon, port
# @deps:  nmap
# @usage: bash network/recon/nmap_quick.sh 10.10.10.5 [full|quick|udp|ping]
# 注意: 許可された対象（CTF 環境・自組織資産）にのみ実行すること
set -euo pipefail

usage() {
  cat >&2 <<USAGE
usage: $0 <target> [mode]
  full  (default) 全 TCP ポートを高速発見 → 開いたポートに -sC -sV
  quick           top 1000 ポートに -sC -sV
  udp             top 100 UDP ポート（要 root）
  ping            ホスト発見のみ（-sn、CIDR 指定向け）
結果は ./nmap_<target>_<mode>.* に保存されます
USAGE
  exit 1
}
[[ $# -ge 1 ]] || usage
command -v nmap >/dev/null || { echo "error: nmap が見つかりません (brew install nmap / apt install nmap)" >&2; exit 1; }

target=$1
mode=${2:-full}
out="nmap_${target//\//_}_${mode}"

case $mode in
  full)
    nmap -p- --min-rate 2000 -T4 -n -Pn -oG "${out}_ports.gnmap" "$target"
    ports=$(grep -oE '[0-9]+/open' "${out}_ports.gnmap" | cut -d/ -f1 | sort -un | paste -sd, -)
    if [[ -z $ports ]]; then echo "open ports not found"; exit 0; fi
    echo "[+] open ports: $ports"
    nmap -p "$ports" -sC -sV -n -Pn -oA "$out" "$target"
    ;;
  quick) nmap -sC -sV -T4 -n -Pn -oA "$out" "$target" ;;
  udp)   sudo nmap -sU --top-ports 100 -T4 -n -Pn -oA "$out" "$target" ;;
  ping)  nmap -sn -n -oA "$out" "$target" ;;
  *) usage ;;
esac
