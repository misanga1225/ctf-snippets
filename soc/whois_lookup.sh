#!/usr/bin/env bash
# @desc:  IP/ドメインの whois・DNS レコード・逆引きをまとめて取得
# @tags:  soc, noc, whois, dns, dig, osint
# @deps:  whois, dig
# @usage: bash soc/whois_lookup.sh example.com 8.8.8.8
set -euo pipefail

usage() { echo "usage: $0 <domain|ip> [...]" >&2; exit 1; }
[[ $# -ge 1 ]] || usage
for cmd in whois dig; do
  command -v "$cmd" >/dev/null || { echo "error: '$cmd' が見つかりません" >&2; exit 1; }
done

is_ip() { [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || $1 == *:* ]]; }

for target in "$@"; do
  # defang 表記 (example[.]com) をそのまま貼っても動くように
  target=${target//\[.\]/.}
  echo "==================== $target ===================="
  if is_ip "$target"; then
    echo "## PTR (逆引き)"
    dig +short -x "$target" || true
    echo "## whois (要約)"
    whois "$target" 2>/dev/null \
      | grep -iE '^(netname|orgname|org-name|organization|descr|country|cidr|inetnum|netrange|origin|originas|abuse-mailbox|orgabuseemail)' \
      | sort -u || true
  else
    for rr in A AAAA CNAME MX NS TXT; do
      res=$(dig +short "$target" "$rr" || true)
      [[ -n $res ]] && { echo "## $rr"; echo "$res"; }
    done
    echo "## whois (要約)"
    whois "$target" 2>/dev/null \
      | grep -iE '^\s*(domain name|registrar:|creation date|created|updated date|registry expiry|expir|name server|registrant (organization|country)|status)' \
      | sort -u || true
  fi
  echo
done
