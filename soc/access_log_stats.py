#!/usr/bin/env python3
# @desc:  Apache/Nginx アクセスログ (combined) の集計と怪しいリクエスト（SQLi/XSS/LFI/スキャナ）検出
# @tags:  soc, log, web, apache, nginx, sqli, xss, lfi, ctf
# @deps:  none
# @usage: python3 soc/access_log_stats.py access.log --suspicious
import argparse
import gzip
import re
import sys
from collections import Counter
from urllib.parse import unquote_plus

COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)

SUSPICIOUS = {
    "sqli": re.compile(r"union\s+select|or\s+1=1|'\s*or\s*'|sleep\(|benchmark\(|information_schema", re.I),
    "xss": re.compile(r"<script|javascript:|onerror\s*=|onload\s*=|alert\(", re.I),
    "lfi/traversal": re.compile(r"\.\./|/etc/passwd|php://|file://|%00", re.I),
    "rce": re.compile(r";\s*(?:id|whoami|cat|wget|curl)\b|\$\(|`|cmd\.exe|/bin/(?:ba)?sh", re.I),
    "scanner": re.compile(r"nikto|sqlmap|nmap|dirbuster|gobuster|ffuf|wpscan|masscan|zgrab", re.I),
    "sensitive": re.compile(r"/\.git|/\.env|wp-admin|phpmyadmin|/admin|\.bak$|\.sql$", re.I),
}


def open_log(path):
    if path == "-":
        return sys.stdin
    opener = gzip.open if path.endswith(".gz") else open
    return opener(path, "rt", encoding="utf-8", errors="replace")


def main():
    p = argparse.ArgumentParser(description="Web アクセスログ集計")
    p.add_argument("logs", nargs="*", default=["-"], help="ログファイル（.gz 可、省略時は stdin）")
    p.add_argument("-n", "--top", type=int, default=10, help="各ランキングの表示件数")
    p.add_argument("--suspicious", action="store_true", help="怪しいリクエストを行単位で表示")
    p.add_argument("--ip", help="特定 IP のリクエストのみ対象にする")
    args = p.parse_args()

    stats = {k: Counter() for k in ("ip", "status", "path", "ua", "method")}
    hits = Counter()
    total = 0
    for path in args.logs:
        with open_log(path) as f:
            for line in f:
                m = COMBINED.match(line)
                if not m or (args.ip and m["ip"] != args.ip):
                    continue
                total += 1
                for k in stats:
                    stats[k][m[k] or "-"] += 1
                decoded = unquote_plus(m["path"]) + " " + (m["ua"] or "")
                for kind, pat in SUSPICIOUS.items():
                    if pat.search(decoded):
                        hits[kind] += 1
                        if args.suspicious:
                            print(f"[{kind}] {m['ip']} {m['time']} {m['status']} {unquote_plus(m['path'])}")

    if args.suspicious:
        print()
    print(f"total requests: {total}")
    for k, title in [("ip", "送信元 IP"), ("status", "ステータス"), ("method", "メソッド"),
                     ("path", "パス"), ("ua", "User-Agent")]:
        print(f"\n## {title} top {args.top}")
        for v, n in stats[k].most_common(args.top):
            print(f"{n:>8}  {v}")
    if hits:
        print("\n## 怪しいリクエスト検出数")
        for kind, n in hits.most_common():
            print(f"{n:>8}  {kind}")


if __name__ == "__main__":
    main()
