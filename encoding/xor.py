#!/usr/bin/env python3
# @desc:  XOR（単一/複数バイト鍵）、単一バイト鍵の総当たり、既知平文からの鍵推定
# @tags:  ctf, encoding, xor, crypto, bruteforce
# @deps:  none
# @usage: python3 encoding/xor.py -k 0x42 -i hex 242e2325393a3f
import argparse
import string
import sys

PRINTABLE = set(string.printable.encode())
TEXTY = set((string.ascii_letters + string.digits + " _{}").encode())


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def parse_key(k: str) -> bytes:
    if k.lower().startswith("0x"):
        h = k[2:]
        return bytes.fromhex(h if len(h) % 2 == 0 else "0" + h)
    return k.encode()


def score(b: bytes) -> float:
    """平文らしさ: 印字不可があれば 0、それ以外は英数字・空白・{}_ の割合"""
    if any(x not in PRINTABLE for x in b):
        return 0.0
    return sum(x in TEXTY for x in b) / max(1, len(b))


def main():
    p = argparse.ArgumentParser(description="XOR ツール")
    p.add_argument("-k", "--key", help="鍵（'0x41ff' で hex、それ以外は文字列）")
    p.add_argument("--brute", action="store_true", help="単一バイト鍵 0x00-0xff を総当たり")
    p.add_argument("--known", help="既知平文の先頭（例: 'flag{'）から繰り返し鍵を推定")
    p.add_argument("-i", "--in-format", choices=["raw", "hex"], default="raw", help="入力形式")
    p.add_argument("-o", "--out-format", choices=["raw", "hex"], default="raw", help="出力形式")
    p.add_argument("--top", type=int, default=5, help="--brute で表示する上位件数 (default: 5)")
    p.add_argument("data", nargs="?", help="入力（省略時は stdin）")
    args = p.parse_args()

    if args.data is not None:
        data = args.data.encode()
    else:
        data = sys.stdin.buffer.read()
    if args.in_format == "hex":
        data = bytes.fromhex(data.decode().strip().replace(" ", ""))

    if args.known:
        known = args.known.encode()
        key = xor(data[: len(known)], known)
        print(f"key (hex): {key.hex()}  key (str): {key!r}")
        return
    if args.brute:
        results = [(b"flag{" in (r := xor(data, bytes([k]))).lower(), score(r), k, r) for k in range(256)]
        for _, sc, k, r in sorted(results, reverse=True)[: args.top]:
            if sc:
                print(f"0x{k:02x} ({sc:.0%}): {r.decode(errors='replace')}")
        return
    if not args.key:
        p.error("-k / --brute / --known のいずれかを指定してください")
    out = xor(data, parse_key(args.key))
    if args.out_format == "hex":
        print(out.hex())
    else:
        sys.stdout.buffer.write(out)
        if sys.stdout.isatty():
            print()


if __name__ == "__main__":
    main()
