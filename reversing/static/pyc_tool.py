#!/usr/bin/env python3
# @desc:  .pyc の Python バージョン判定・ヘッダ修復（pyinstxtractor 出力向け）・逆アセンブル/定数一覧（同バージョンの Python で実行時）
# @tags:  ctf, reversing, static, python, pyc, pyinstaller, marshal, dis, decompile
# @deps:  none（逆コンパイルは pycdc / decompyle3 / uncompyle6 を別途）
# @usage: python3 reversing/static/pyc_tool.py info chall.pyc
"""サブコマンド:
  info  FILE              マジックナンバーから Python バージョンを判定し、使うべき逆コンパイラを提案
  fix   FILE --ver 3.10   ヘッダが欠けた pyc（PyInstaller の PYZ 内モジュール等）に正しいヘッダを付ける
  dis   FILE              逆アセンブル（pyc と同じバージョンの python3.X で実行すること）
  consts FILE             全コードオブジェクトの文字列/数値定数・名前を一覧（flag や鍵がそのまま入っていることが多い）
"""
import argparse
import dis
import importlib.util
import marshal
import struct
import sys
import types

# マジックナンバー（先頭 2 バイト LE）の範囲 → バージョン（CPython Lib/importlib/_bootstrap_external.py より）
RANGES = [(3000, 3131, "3.0"), (3141, 3151, "3.1"), (3160, 3180, "3.2"), (3190, 3230, "3.3"), (3250, 3310, "3.4"),
          (3320, 3351, "3.5"), (3360, 3379, "3.6"), (3390, 3399, "3.7"), (3400, 3419, "3.8"), (3420, 3429, "3.9"),
          (3430, 3449, "3.10"), (3450, 3499, "3.11"), (3500, 3549, "3.12"), (3550, 3599, "3.13"),
          (3600, 3649, "3.14"), (3650, 3699, "3.15")]
# 各バージョンの正式リリース時のマジック（fix 用）
FINAL_MAGIC = {"2.7": 62211, "3.5": 3351, "3.6": 3379, "3.7": 3394, "3.8": 3413, "3.9": 3425, "3.10": 3439,
               "3.11": 3495, "3.12": 3531, "3.13": 3571}
DECOMPILERS = {
    "2.7": "uncompyle6 / decompyle3 で高精度に戻る",
    "3.6": "uncompyle6 / decompyle3（3.7, 3.8 も可）",
    "3.7": "decompyle3 / uncompyle6",
    "3.8": "decompyle3 / uncompyle6",
}


def version_of(magic: int) -> str:
    if 62000 <= magic < 63000:
        return "2.7" if magic == 62211 else "2.x"
    for lo, hi, v in RANGES:
        if lo <= magic <= hi:
            return v
    return "unknown"


def header_size(ver: str) -> int:
    if ver.startswith("2"):
        return 8
    minor = int(ver.split(".")[1]) if ver[0] == "3" and ver != "unknown" else 99
    return 12 if minor < 7 else 16


def load_code(path):
    data = open(path, "rb").read()
    magic = struct.unpack_from("<H", data)[0]
    ver = version_of(magic)
    running = f"{sys.version_info.major}.{sys.version_info.minor}"
    if data[:4] != importlib.util.MAGIC_NUMBER:
        sys.exit(f"error: この pyc は Python {ver} 用（magic {magic}）。marshal は同じバージョンでしか読めません。\n"
                 f"       python{ver} で実行してください（例: uv run --python {ver} {' '.join(sys.argv)}）。"
                 f" 現在: {running}")
    return marshal.loads(data[header_size(ver):])


def walk(code, depth=0):
    yield code, depth
    for c in code.co_consts:
        if isinstance(c, types.CodeType):
            yield from walk(c, depth + 1)


def cmd_info(args):
    data = open(args.file, "rb").read(32)
    magic = struct.unpack_from("<H", data)[0]
    ver = version_of(magic)
    print(f"magic     : {magic} ({data[:4].hex(' ')})")
    print(f"version   : Python {ver}")
    if data[2:4] != b"\r\n":
        print("warning   : 3-4 バイト目が 0d 0a ではありません → ヘッダが欠けている可能性。`fix --ver 3.X` を試す")
        return
    hs = header_size(ver)
    if hs == 16:
        flags = struct.unpack_from("<I", data, 4)[0]
        if flags & 1:
            print(f"header    : 16 bytes, hash-based (source hash {data[8:16].hex()})")
        else:
            mtime, size = struct.unpack_from("<II", data, 8)
            print(f"header    : 16 bytes, timestamp {mtime}, source size {size}")
    else:
        print(f"header    : {hs} bytes")
    print("\n逆コンパイルの候補:")
    print(f"  {DECOMPILERS.get(ver, 'pycdc (Decompyle++)。3.9 以降は完全には戻らないことが多い → 失敗部分は dis で読む')}")
    print("  オンライン: PyLingual (https://pylingual.io) は 3.9〜3.13 に強い")
    print(f"  逆アセンブル: python{ver} {sys.argv[0]} dis {args.file}")


def cmd_fix(args):
    data = open(args.file, "rb").read()
    running = f"{sys.version_info.major}.{sys.version_info.minor}"
    if args.ver == running:
        magic = importlib.util.MAGIC_NUMBER
    elif args.ver in FINAL_MAGIC:
        magic = struct.pack("<H", FINAL_MAGIC[args.ver]) + b"\r\n"
    else:
        sys.exit(f"error: {args.ver} のマジックが不明です。python{args.ver} 自身で実行すれば自動で取得します")
    hs = header_size(args.ver)
    if data[2:4] == b"\r\n":
        print("note: すでにマジックがあるため既存ヘッダを置き換えます", file=sys.stderr)
        data = data[header_size(version_of(struct.unpack_from('<H', data)[0])):]
    out = args.output or args.file.rsplit(".", 1)[0] + "_fixed.pyc"
    with open(out, "wb") as f:
        f.write(magic + b"\0" * (hs - 4) + data)
    print(f"[+] {out}  (magic {magic[:2].hex()} = Python {args.ver}, header {hs} bytes)")


def cmd_dis(args):
    code = load_code(args.file)
    for c, depth in walk(code):
        print(f"\n{'#' * 70}\n# {c.co_name}  ({c.co_filename}:{c.co_firstlineno})\n{'#' * 70}")
        dis.dis(c, depth=0) if sys.version_info >= (3, 7) else dis.dis(c)


def cmd_consts(args):
    code = load_code(args.file)
    for c, depth in walk(code):
        consts = [k for k in c.co_consts if not isinstance(k, types.CodeType) and k is not None]
        print(f"{'  ' * depth}[{c.co_name}] names={list(c.co_names)}")
        for k in consts:
            print(f"{'  ' * depth}    {k!r}")


def main():
    p = argparse.ArgumentParser(description="pyc 解析ツール", formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n", 1)[1])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("info")
    s.add_argument("file")
    s.set_defaults(func=cmd_info)
    s = sub.add_parser("fix")
    s.add_argument("file")
    s.add_argument("--ver", required=True, help="付与するバージョン（例: 3.10）。PyInstaller 本体の pyc 等から判定")
    s.add_argument("-o", "--output")
    s.set_defaults(func=cmd_fix)
    s = sub.add_parser("dis")
    s.add_argument("file")
    s.set_defaults(func=cmd_dis)
    s = sub.add_parser("consts")
    s.add_argument("file")
    s.set_defaults(func=cmd_consts)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
