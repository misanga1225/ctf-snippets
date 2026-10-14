#!/usr/bin/env python3
# @desc:  DNS トンネル/サブドメインに埋め込まれたデータを結合・復元（hex/base32/base64 自動試行）
# @tags:  ctf, soc, network, pcap, dns, exfiltration, tunnel, tshark
# @deps:  tshark（クエリ名リストを stdin で渡す場合は不要）
# @usage: python3 network/pcap/dns_exfil.py capture.pcap --domain evil.com -o out.bin
import argparse
import base64
import binascii
import subprocess
import sys


def query_names(pcap: str, domain: str):
    flt = "dns.flags.response == 0"
    if domain:
        flt += f' and dns.qry.name contains "{domain}"'
    out = subprocess.run(["tshark", "-r", pcap, "-Y", flt, "-T", "fields", "-e", "dns.qry.name"],
                         capture_output=True, text=True, check=True).stdout
    return [line.split(",")[0] for line in out.splitlines() if line]


def strip_domain(name: str, domain: str) -> str:
    name = name.rstrip(".")
    if domain and name.endswith(domain):
        name = name[: -len(domain)].rstrip(".")
    return name.replace(".", "")  # 複数ラベルに分割されたデータを連結


def try_decodes(data: str):
    cands = []
    for label, func in [
        ("hex", lambda s: bytes.fromhex(s)),
        ("base32", lambda s: base64.b32decode(s.upper() + "=" * (-len(s) % 8))),
        ("base64", lambda s: base64.b64decode(s + "=" * (-len(s) % 4), validate=True)),
        ("base64url", lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))),
    ]:
        try:
            cands.append((label, func(data)))
        except (ValueError, binascii.Error):
            pass
    return cands


def main():
    p = argparse.ArgumentParser(description="DNS exfil データの復元")
    p.add_argument("pcap", nargs="?", help="pcap ファイル（省略時は stdin からクエリ名を 1 行ずつ読む）")
    p.add_argument("-d", "--domain", default="", help="exfil 先ドメイン（このサフィックスを除去）")
    p.add_argument("--keep-dups", action="store_true", help="連続する重複クエリ（再送）を除去しない")
    p.add_argument("-o", "--output", help="デコード結果（最も印字可能なもの or --codec 指定）を保存")
    p.add_argument("--codec", choices=["hex", "base32", "base64", "base64url", "raw"], help="デコード方式を固定")
    args = p.parse_args()

    names = query_names(args.pcap, args.domain) if args.pcap else sys.stdin.read().split()
    if args.domain:
        names = [n for n in names if n.rstrip(".").endswith(args.domain)]
    chunks = []
    for n in names:
        c = strip_domain(n, args.domain)
        if c and (args.keep_dups or not chunks or chunks[-1] != c):
            chunks.append(c)
    joined = "".join(chunks)
    print(f"[+] {len(names)} queries -> {len(chunks)} chunks, {len(joined)} chars", file=sys.stderr)
    print(f"[raw] {joined[:200]}{'...' if len(joined) > 200 else ''}")

    cands = [("raw", joined.encode())] if args.codec == "raw" else try_decodes(joined)
    if args.codec and args.codec != "raw":
        cands = [c for c in cands if c[0] == args.codec]
    for label, data in cands:
        print(f"[{label}] {data[:200]!r}")
    if args.output and cands:
        best = max(cands, key=lambda c: sum(32 <= b < 127 for b in c[1]) / max(1, len(c[1])))
        with open(args.output, "wb") as f:
            f.write(best[1])
        print(f"[+] saved {best[0]} decoded data -> {args.output}（file コマンドで種別確認）", file=sys.stderr)


if __name__ == "__main__":
    main()
