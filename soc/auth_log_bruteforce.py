#!/usr/bin/env python3
# @desc:  auth.log / secure から SSH ログイン失敗・成功を IP 別に集計しブルートフォースを検出
# @tags:  soc, log, ssh, bruteforce, auth.log, linux
# @deps:  none
# @usage: python3 soc/auth_log_bruteforce.py /var/log/auth.log -t 10
import argparse
import gzip
import re
import sys
from collections import Counter, defaultdict

FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)")


def open_log(path):
    if path == "-":
        return sys.stdin
    opener = gzip.open if path.endswith(".gz") else open
    return opener(path, "rt", encoding="utf-8", errors="replace")


def main():
    p = argparse.ArgumentParser(description="SSH 認証ログ集計")
    p.add_argument("logs", nargs="*", default=["-"], help="ログファイル（.gz 可、省略時は stdin）")
    p.add_argument("-t", "--threshold", type=int, default=5, help="この回数以上失敗した IP を表示 (default: 5)")
    args = p.parse_args()

    fails = Counter()
    fail_users = defaultdict(Counter)
    accepted = []
    for path in args.logs:
        with open_log(path) as f:
            for line in f:
                if m := FAILED.search(line):
                    fails[m["ip"]] += 1
                    fail_users[m["ip"]][m["user"]] += 1
                elif m := ACCEPTED.search(line):
                    accepted.append((m["ip"], m["user"], m["method"], line[:15]))

    print(f"## 失敗回数 >= {args.threshold} の送信元")
    print(f"{'count':>7}  {'ip':<40} top users")
    for ip, n in fails.most_common():
        if n < args.threshold:
            break
        users = ", ".join(f"{u}({c})" for u, c in fail_users[ip].most_common(5))
        print(f"{n:>7}  {ip:<40} {users}")

    print("\n## ログイン成功")
    for ip, user, method, ts in accepted:
        mark = "  <-- 失敗履歴あり!" if ip in fails else ""
        print(f"{ts}  {user:<15} {ip:<40} {method}{mark}")


if __name__ == "__main__":
    main()
