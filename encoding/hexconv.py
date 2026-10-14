#!/usr/bin/env python3
# @desc:  hex / bytes / 整数 / 2進数 / 10進バイト列の相互変換
# @tags:  ctf, encoding, hex, binary, int, long_to_bytes
# @deps:  none
# @usage: python3 encoding/hexconv.py -f hex -t str 666c61677b787d
import argparse
import re
import sys


def to_bytes(data: str, fmt: str) -> bytes:
    if fmt == "str":
        return data.encode()
    if fmt == "hex":
        s = re.sub(r"0x|\\x|[\s:,-]", "", data)
        return bytes.fromhex(s if len(s) % 2 == 0 else "0" + s)
    if fmt == "int":
        n = int(data.strip(), 0)
        return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if fmt == "bin":
        s = re.sub(r"[^01]", "", data)
        s = s.zfill(-(-len(s) // 8) * 8)
        return int(s, 2).to_bytes(len(s) // 8, "big")
    if fmt == "dec":  # "102 108 97 103" 形式
        return bytes(int(x) for x in re.split(r"[\s,]+", data.strip()) if x)
    raise ValueError(fmt)


def from_bytes(b: bytes, fmt: str) -> str:
    if fmt == "str":
        return b.decode(errors="backslashreplace")
    if fmt == "hex":
        return b.hex()
    if fmt == "int":
        return str(int.from_bytes(b, "big"))
    if fmt == "bin":
        return " ".join(f"{x:08b}" for x in b)
    if fmt == "dec":
        return " ".join(str(x) for x in b)
    if fmt == "pyhex":
        return "".join(f"\\x{x:02x}" for x in b)
    raise ValueError(fmt)


def main():
    fmts = ["str", "hex", "int", "bin", "dec"]
    p = argparse.ArgumentParser(description="hex/bytes/int/bin 相互変換")
    p.add_argument("-f", "--from", dest="src", choices=fmts, default="hex", help="入力形式 (default: hex)")
    p.add_argument("-t", "--to", dest="dst", choices=fmts + ["pyhex", "all"], default="all",
                   help="出力形式 (default: all = 全形式表示)")
    p.add_argument("data", nargs="?", help="入力（省略時は stdin）")
    args = p.parse_args()

    data = args.data if args.data is not None else sys.stdin.read().rstrip("\n")
    b = to_bytes(data, args.src)
    if args.dst == "all":
        for f in ["str", "hex", "int", "bin", "dec", "pyhex"]:
            print(f"{f:>5}: {from_bytes(b, f)}")
    else:
        print(from_bytes(b, args.dst))


if __name__ == "__main__":
    main()
