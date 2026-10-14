#!/usr/bin/env python3
# @desc:  多段エンコードを自動判定してデコード（CyberChef Magic 簡易版、flag 形式を検出）
# @tags:  ctf, encoding, magic, auto, base64, hex, rot13, url
# @deps:  none
# @usage: python3 encoding/auto_decode.py 'NjY2YzYxNjc3Yjc4N2Q='
import argparse
import base64
import binascii
import codecs
import re
import string
import sys
from urllib.parse import unquote_to_bytes

PRINTABLE = set(string.printable.encode())


def _b58(data: bytes) -> bytes:
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in data:
        n = n * 58 + alphabet.index(ch)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _pad(d: bytes, block: int) -> bytes:
    return d + b"=" * (-len(d) % block)


# (名前, 入力がその形式らしいかの判定 regex, デコード関数)
DECODERS = [
    ("hex", rb"^(?:[0-9a-fA-F]{2})+$", lambda d: bytes.fromhex(d.decode())),
    ("base32", rb"^[A-Z2-7]+=*$", lambda d: base64.b32decode(_pad(d, 8))),
    ("base64", rb"^[A-Za-z0-9+/]+=*$", lambda d: base64.b64decode(_pad(d, 4), validate=True)),
    ("base64url", rb"^[A-Za-z0-9_-]+=*$", lambda d: base64.urlsafe_b64decode(_pad(d, 4))),
    ("base58", rb"^[1-9A-HJ-NP-Za-km-z]+$", _b58),
    ("base85", rb"^[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+$", base64.b85decode),
    ("binary", rb"^[01 ]+$", lambda d: int(d.replace(b" ", b""), 2).to_bytes(len(d.replace(b" ", b"")) // 8, "big")),
    ("decimal", rb"^\d{2,3}(?:[ ,]\d{2,3})+$", lambda d: bytes(int(x) for x in re.split(rb"[ ,]", d))),
    ("url", rb"%[0-9a-fA-F]{2}", unquote_to_bytes),
    ("rot13", rb"^[\x20-\x7e]+$", lambda d: codecs.encode(d.decode(), "rot13").encode()),
]


def printable_ratio(b: bytes) -> float:
    return sum(x in PRINTABLE for x in b) / max(1, len(b))


def search(data: bytes, flag_re, max_depth: int):
    """深さ優先で全デコード経路を試し、flag 形式に一致した経路を返す。
    一致しても探索は続ける（rot13 済みの 'synt{...}' 等も一致するため）"""
    found, seen = {}, set()

    def dfs(cur: bytes, path):
        if flag_re.search(cur) and (cur not in found or len(path) < len(found[cur])):
            found[cur] = path
        if len(path) >= max_depth or cur in seen:
            return
        seen.add(cur)
        stripped = cur.strip()
        for name, pattern, func in DECODERS:
            if path and path[-1] == "rot13" and name == "rot13":
                continue
            if not re.search(pattern, stripped):
                continue
            try:
                out = func(stripped)
            except (ValueError, binascii.Error, UnicodeDecodeError, OverflowError):
                continue
            # rot13 は何にでも適用できるので、flag に近づかない限り深追いしない
            if not out or out == stripped or (name != "rot13" and printable_ratio(out) < 0.9):
                continue
            dfs(out, path + [name])

    dfs(data, [])
    return found


def main():
    p = argparse.ArgumentParser(description="多段エンコードの自動デコード")
    p.add_argument("data", nargs="?", help="入力（省略時は stdin）")
    p.add_argument("-f", "--flag", default=r"[A-Za-z0-9_]*\{[^}]+\}",
                   help="flag 形式の正規表現 (default: xxx{...})")
    p.add_argument("--depth", type=int, default=8, help="最大デコード段数 (default: 8)")
    args = p.parse_args()

    data = (args.data.encode() if args.data is not None else sys.stdin.buffer.read()).strip()
    results = search(data, re.compile(args.flag.encode()), args.depth)
    if not results:
        sys.exit("flag 形式に一致する結果は見つかりませんでした（--flag / --depth を調整してください）")
    # 'flag{' を含むものを優先し、次に経路が短い順
    ranked = sorted(results.items(), key=lambda r: (b"flag{" not in r[0].lower(), len(r[1])))
    for out, path in ranked:
        print(f"[{' -> '.join(path) or 'raw'}] {out.strip().decode(errors='replace')}")


if __name__ == "__main__":
    main()
