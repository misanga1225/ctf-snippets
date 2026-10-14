#!/usr/bin/env python3
# @desc:  URL エンコード / デコード（多重エンコードの完全デコード対応）
# @tags:  ctf, encoding, url, percent, web
# @deps:  none
# @usage: python3 encoding/urlenc.py -d --full '%2566lag%257B%2578%257D'
import argparse
import sys
from urllib.parse import quote, unquote, unquote_plus


def main():
    p = argparse.ArgumentParser(description="URL エンコード/デコード")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-d", "--decode", action="store_true", help="デコード（デフォルト）")
    g.add_argument("-e", "--encode", action="store_true", help="エンコード")
    p.add_argument("--all", action="store_true", help="エンコード時に英数字含め全文字を %%XX 化")
    p.add_argument("--plus", action="store_true", help="'+' を空白として扱う（フォーム形式）")
    p.add_argument("--full", action="store_true", help="変化しなくなるまで繰り返しデコード")
    p.add_argument("data", nargs="?", help="入力（省略時は stdin）")
    args = p.parse_args()

    data = args.data if args.data is not None else sys.stdin.read().rstrip("\n")
    if args.encode:
        if args.all:
            print("".join(f"%{b:02X}" for b in data.encode()))
        else:
            print(quote(data, safe=""))
        return
    dec = unquote_plus if args.plus else unquote
    if not args.full:
        print(dec(data))
        return
    layer = 0
    while (nxt := dec(data)) != data:
        layer += 1
        data = nxt
        print(f"[layer {layer}] {data}", file=sys.stderr)
    print(data)


if __name__ == "__main__":
    main()
