#!/usr/bin/env python3
# @desc:  CIDR 計算（ネットワーク/ブロードキャスト/ホスト範囲/包含判定/サブネット分割）
# @tags:  noc, network, cidr, subnet, ipv4, ipv6
# @deps:  none
# @usage: python3 network/recon/subnet_calc.py 192.168.10.37/22 --contains 192.168.11.5 --split 24
import argparse
import ipaddress


def main():
    p = argparse.ArgumentParser(description="CIDR 計算")
    p.add_argument("cidr", help="例: 10.0.0.5/24, 2001:db8::/48, 192.168.0.0/255.255.252.0")
    p.add_argument("--contains", nargs="+", metavar="IP", help="これらの IP が含まれるか判定")
    p.add_argument("--split", type=int, metavar="PREFIX", help="指定プレフィックス長に分割して列挙")
    p.add_argument("--list", action="store_true", help="ホスト IP を全列挙（nmap/for ループ用）")
    args = p.parse_args()

    iface = ipaddress.ip_interface(args.cidr)
    net = iface.network
    print(f"input      : {iface}")
    print(f"network    : {net.network_address}/{net.prefixlen}")
    if net.version == 4:
        print(f"netmask    : {net.netmask}")
        print(f"wildcard   : {net.hostmask}")
        print(f"broadcast  : {net.broadcast_address}")
    hosts = net.num_addresses - (2 if net.version == 4 and net.prefixlen < 31 else 0)
    if net.num_addresses > 1:
        first = net.network_address + (1 if net.version == 4 and net.prefixlen < 31 else 0)
        last = net.broadcast_address - (1 if net.version == 4 and net.prefixlen < 31 else 0)
        print(f"host range : {first} - {last}")
    print(f"hosts      : {hosts:,}")
    print(f"private    : {net.is_private}")

    if args.contains:
        print()
        for ip in args.contains:
            print(f"{ip:<20} {'IN' if ipaddress.ip_address(ip) in net else 'OUT'}")
    if args.split:
        print()
        for sub in net.subnets(new_prefix=args.split):
            print(sub)
    if args.list:
        print()
        for h in net.hosts():
            print(h)


if __name__ == "__main__":
    main()
