#!/usr/bin/env python3
# @desc:  base64 / base32 / base85 / ascii85 / base58 のエンコード・デコード
# @tags:  ctf, encoding, base64, base32, base58, base85
# @deps:  none
# @usage: echo 'ZmxhZ3t4fQ==' | python3 encoding/b64.py -d
import argparse
import base64
import sys

B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> bytes:
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n:
        n, r = divmod(n, 58)
        out.append(B58_ALPHABET[r])
    pad = len(data) - len(data.lstrip(b"\0"))
    return B58_ALPHABET[:1] * pad + bytes(reversed(out))


def b58decode(data: bytes) -> bytes:
    data = data.strip()
    n = 0
    for ch in data:
        n = n * 58 + B58_ALPHABET.index(ch)
    pad = len(data) - len(data.lstrip(B58_ALPHABET[:1]))
    return b"\0" * pad + n.to_bytes((n.bit_length() + 7) // 8, "big")


def fix_padding(data: bytes, block: int) -> bytes:
    """パディング欠落を補完（CTF ではよく '=' が削られている）"""
    data = b"".join(data.split())
    return data + b"=" * (-len(data) % block)


CODECS = {
    "64": (base64.b64encode, lambda d: base64.b64decode(fix_padding(d, 4))),
    "64url": (base64.urlsafe_b64encode, lambda d: base64.urlsafe_b64decode(fix_padding(d, 4))),
    "32": (base64.b32encode, lambda d: base64.b32decode(fix_padding(d.upper(), 8))),
    "85": (base64.b85encode, base64.b85decode),
    "a85": (base64.a85encode, lambda d: base64.a85decode(d, adobe=d.strip().startswith(b"<~"))),
    "58": (b58encode, b58decode),
}


def main():
    p = argparse.ArgumentParser(description="base 系エンコード/デコード")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-d", "--decode", action="store_true", help="デコード（デフォルト）")
    g.add_argument("-e", "--encode", action="store_true", help="エンコード")
    p.add_argument("-v", "--variant", choices=CODECS, default="64", help="種類 (default: 64)")
    p.add_argument("-n", "--times", type=int, default=1, help="繰り返し回数（多重エンコード用）")
    p.add_argument("data", nargs="?", help="入力文字列（省略時は stdin）")
    args = p.parse_args()

    data = args.data.encode() if args.data is not None else sys.stdin.buffer.read()
    enc, dec = CODECS[args.variant]
    func = enc if args.encode else dec
    if not args.encode:
        data = data.strip()
    for _ in range(args.times):
        data = func(data)
    sys.stdout.buffer.write(data)
    if args.encode or sys.stdout.isatty():
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
