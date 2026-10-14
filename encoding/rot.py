#!/usr/bin/env python3
# @desc:  ROT13 / ROT-N / ROT47 / Caesar 全シフト総当たり
# @tags:  ctf, encoding, rot13, rot47, caesar, classical
# @deps:  none
# @usage: python3 encoding/rot.py --brute 'synt{ebg13}'
import argparse
import sys


def rot_n(text: str, n: int) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + n) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + n) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def rot47(text: str) -> str:
    return "".join(chr(33 + (ord(ch) - 33 + 47) % 94) if 33 <= ord(ch) <= 126 else ch for ch in text)


def main():
    p = argparse.ArgumentParser(description="ROT/Caesar 変換")
    p.add_argument("-n", type=int, default=13, help="シフト数 (default: 13)")
    p.add_argument("--rot47", action="store_true", help="ROT47 を使う")
    p.add_argument("--brute", action="store_true", help="1〜25 の全シフトを表示")
    p.add_argument("--grep", default=None, help="--brute 時、この文字列を含む結果のみ表示（例: flag）")
    p.add_argument("data", nargs="?", help="入力（省略時は stdin）")
    args = p.parse_args()

    data = args.data if args.data is not None else sys.stdin.read().rstrip("\n")
    if args.rot47:
        print(rot47(data))
    elif args.brute:
        for n in range(1, 26):
            res = rot_n(data, n)
            if args.grep is None or args.grep.lower() in res.lower():
                print(f"ROT{n:>2}: {res}")
    else:
        print(rot_n(data, args.n))


if __name__ == "__main__":
    main()
