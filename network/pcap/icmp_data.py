#!/usr/bin/env python3
# @desc:  ICMP ペイロードを結合して隠しデータを抽出（1 パケット 1 バイト型・TTL/ID 埋め込み型にも対応）
# @tags:  ctf, network, pcap, icmp, ping, covert-channel, exfiltration, tshark
# @deps:  tshark
# @usage: python3 network/pcap/icmp_data.py capture.pcap --type request --offset 0 --length 1
import argparse
import subprocess
import sys

TYPES = {"request": "icmp.type == 8", "reply": "icmp.type == 0", "all": "icmp"}


def main():
    p = argparse.ArgumentParser(description="ICMP 隠しデータ抽出")
    p.add_argument("pcap")
    p.add_argument("--type", choices=TYPES, default="request", help="対象 (default: request)")
    p.add_argument("--field", default="data.data",
                   help="抽出フィールド (default: data.data / 例: ip.ttl, ip.id, icmp.seq)")
    p.add_argument("--offset", type=int, default=0, help="各ペイロードの切り出し開始位置")
    p.add_argument("--length", type=int, default=None, help="各ペイロードの切り出しバイト数（省略時は全体）")
    p.add_argument("--src", help="送信元 IP で絞り込み")
    p.add_argument("-o", "--output", help="結合結果をバイナリで保存")
    args = p.parse_args()

    flt = TYPES[args.type] + (f" and ip.src == {args.src}" if args.src else "")
    out = subprocess.run(["tshark", "-r", args.pcap, "-Y", flt, "-T", "fields", "-e", args.field],
                         capture_output=True, text=True, check=True).stdout
    data = bytearray()
    for line in out.splitlines():
        if not line:
            continue
        if args.field == "data.data":
            chunk = bytes.fromhex(line.replace(":", ""))
        else:  # ip.ttl などの数値フィールドは 1 バイトとして扱う
            chunk = bytes([int(line.split(",")[0], 0) & 0xFF])
        end = None if args.length is None else args.offset + args.length
        data += chunk[args.offset:end]

    print(f"[+] {len(out.splitlines())} packets -> {len(data)} bytes", file=sys.stderr)
    if args.output:
        with open(args.output, "wb") as f:
            f.write(data)
        print(f"[+] saved -> {args.output}", file=sys.stderr)
    else:
        print(bytes(data).decode(errors="backslashreplace"))


if __name__ == "__main__":
    main()
