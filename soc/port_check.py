#!/usr/bin/env python3
# @desc:  TCP ポート疎通確認（複数 host:port を並列チェック、応答時間表示）
# @tags:  noc, soc, network, port, tcp, connectivity
# @deps:  none
# @usage: python3 soc/port_check.py example.com:443 10.0.0.1:22,80,3389 -t 2
import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor


def parse_targets(specs):
    """'host:22,80,1000-1010' 形式を (host, port) のリストへ"""
    targets = []
    for spec in specs:
        host, _, ports = spec.rpartition(":")
        host = host.strip("[]")  # [::1]:22 形式
        for part in ports.split(","):
            if "-" in part:
                a, b = map(int, part.split("-"))
                targets += [(host, port) for port in range(a, b + 1)]
            else:
                targets.append((host, int(part)))
    return targets


def check(target, timeout):
    host, port = target
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return host, port, "OPEN", (time.monotonic() - start) * 1000
    except socket.timeout:
        return host, port, "TIMEOUT", None
    except ConnectionRefusedError:
        return host, port, "CLOSED", None
    except OSError as e:
        return host, port, f"ERROR({e.strerror or e})", None


def main():
    p = argparse.ArgumentParser(description="TCP 疎通確認")
    p.add_argument("targets", nargs="+", help="host:port（例: host:22,80 / host:8000-8010）")
    p.add_argument("-t", "--timeout", type=float, default=3.0, help="タイムアウト秒 (default: 3)")
    p.add_argument("-w", "--workers", type=int, default=50, help="並列数 (default: 50)")
    p.add_argument("--open", action="store_true", help="OPEN のみ表示")
    args = p.parse_args()

    with ThreadPoolExecutor(args.workers) as ex:
        for host, port, state, ms in ex.map(lambda t: check(t, args.timeout), parse_targets(args.targets)):
            if args.open and state != "OPEN":
                continue
            rtt = f"{ms:7.1f} ms" if ms is not None else ""
            print(f"{host}:{port:<6} {state:<10} {rtt}")


if __name__ == "__main__":
    main()
