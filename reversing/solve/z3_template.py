#!/usr/bin/env python3
# @desc:  Z3 で「逆コンパイルした判定ロジック」を制約として書いて flag を解くテンプレート（XOR・加算・ローテート・連立式・全解列挙の例つき）
# @tags:  ctf, reversing, solve, z3, smt, constraint, crackme, keygen
# @deps:  z3-solver（pip install z3-solver）
# @usage: python3 reversing/solve/z3_template.py [--all]
"""使い方: check() の中身を Ghidra の疑似 C から書き写すだけ。

書き写しのコツ:
  - 1 文字 = BitVec(8)。演算途中で桁あふれするなら ZeroExt(24, c) で 32bit に広げてから計算
    （C の char は暗黙に int に昇格する。uint8 のまま足すと 256 で巻き戻る）
  - 符号付き比較 <, >  は BitVec では符号付き。符号なしは ULT / UGT / UDiv / URem / LShR を使う
  - (x << 3 | x >> 5) & 0xff  は RotateLeft(x, 3)
  - 配列 table[c] のような参照は Python のリストを If の連鎖にするか z3 Array / 事前に逆写像を作る
  - 解が複数 → --all で列挙。flag 形式（printable, flag{...}）の制約を足して絞る
"""
import argparse
import sys

try:
    from z3 import (And, BitVec, BitVecVal, Or, RotateLeft, Solver, ZeroExt, sat)
except ImportError:
    sys.exit("error: z3 がありません。pip install z3-solver")

FLAG_LEN = 19
# ---- ここに extract_bytes.py で抜き出した比較対象を貼る ----
ENC = [0x75, 0x76, 0x40, 0x4f, 0x54, 0x44, 0x0e, 0x32, 0x14, 0x25, 0x68, 0x14, 0x0f, 0x31, 0x06, 0x12, 0xb2, 0xfa, 0xec]


def add_constraints(s, f):
    """f: 入力文字（BitVec(8)）のリスト。判定ロジックを書き写す"""
    # 例 1: 1 文字ずつ XOR して比較   if ((s[i] ^ (i*7+0x13)) != enc[i]) return 0;
    for i in range(FLAG_LEN):
        s.add(f[i] ^ BitVecVal((i * 7 + 0x13) & 0xFF, 8) == ENC[i])

    # 例 2: 隣同士の和（32bit に広げて桁あふれを防ぐ）   if (s[0] + s[1] != 0xd2) ...
    # s.add(ZeroExt(24, f[0]) + ZeroExt(24, f[1]) == 0xD2)

    # 例 3: ローテート   if (rol8(s[5], 3) != 0x9b) ...
    # s.add(RotateLeft(f[5], 3) == 0x9B)

    # 例 4: 全体のチェックサム   sum(s) == 0x6b1
    # s.add(sum(ZeroExt(24, c) for c in f) == 0x6B1)


def main():
    p = argparse.ArgumentParser(description="z3 テンプレート", formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n", 1)[1])
    p.add_argument("--all", action="store_true", help="全ての解を列挙（最大 --max 件）")
    p.add_argument("--max", type=int, default=20)
    args = p.parse_args()

    f = [BitVec(f"f{i}", 8) for i in range(FLAG_LEN)]
    s = Solver()
    # 共通制約: 印字可能文字 + 既知の flag 形式
    for c in f:
        s.add(And(c >= 0x20, c <= 0x7E))
    for i, ch in enumerate(b"flag{"):
        s.add(f[i] == ch)
    s.add(f[-1] == ord("}"))
    add_constraints(s, f)

    n = 0
    while s.check() == sat:
        m = s.model()
        ans = bytes(m[c].as_long() for c in f)
        print(ans.decode(errors="replace"))
        n += 1
        if not args.all or n >= args.max:
            break
        s.add(Or([c != m[c] for c in f]))  # 今の解を除外して次を探す
    if n == 0:
        print("unsat: 制約が矛盾しています（書き写しミス・桁あふれ・符号の扱いを確認）")


if __name__ == "__main__":
    main()
