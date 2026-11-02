#!/usr/bin/env python3
# @desc:  ファイルをブロックごとにエントロピー計算してグラフ表示（パック・暗号化・圧縮データ領域の発見）
# @tags:  ctf, reversing, surface, entropy, packer, encrypted, compressed
# @deps:  none
# @usage: python3 reversing/surface/entropy.py ./chall [-b 1024] [--threshold 7.2]
"""目安: 0〜1 = ゼロ埋め / 4〜6 = 機械語・テキスト / 7.2〜8 = 圧縮・暗号化・パック済み"""
import argparse
import math
import sys
from collections import Counter


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return max(0.0, -sum(c / n * math.log2(c / n) for c in Counter(b).values()))


def main():
    p = argparse.ArgumentParser(description="ブロック単位エントロピー")
    p.add_argument("file")
    p.add_argument("-b", "--block", type=int, help="ブロックサイズ（省略時は約 64 行になるよう自動）")
    p.add_argument("-t", "--threshold", type=float, default=7.2, help="high と判定する値 (default: 7.2)")
    p.add_argument("--summary", action="store_true", help="全体の値と high 領域だけ表示")
    args = p.parse_args()

    data = open(args.file, "rb").read()
    if not data:
        sys.exit("empty file")
    # ブロックが小さいと乱数でも値が 8 に届かない（256B だと最大 7.2 前後）ので最低 512B にする
    block = args.block or max(512 if len(data) < 16384 else 1024, 1 << max(0, (len(data) // 64 - 1).bit_length()))
    print(f"file entropy: {entropy(data):.3f} / 8.0   size: {len(data)} bytes   block: {block}")

    regions, cur = [], None
    width = 50
    for off in range(0, len(data), block):
        e = entropy(data[off:off + block])
        high = e >= args.threshold
        if high:
            cur = [cur[0], off + block] if cur else [off, off + block]
        elif cur:
            regions.append(cur)
            cur = None
        if not args.summary:
            bar = "#" * round(e / 8 * width)
            print(f"{off:#010x}  {e:5.2f}  {bar:<{width}}{'  <-- high' if high else ''}")
    if cur:
        regions.append(cur)
    if regions:
        print("\nhigh entropy regions（圧縮/暗号化/パックの疑い）:")
        for s, e in regions:
            print(f"  {s:#010x} - {min(e, len(data)):#010x}  ({min(e, len(data)) - s} bytes)")
    else:
        print("\nhigh entropy region なし")


if __name__ == "__main__":
    main()
