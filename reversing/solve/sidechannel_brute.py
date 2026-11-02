#!/usr/bin/env python3
# @desc:  実行命令数のサイドチャネルで flag を 1 文字ずつ総当たり（先頭から比較して不一致で抜ける実装に有効。perf / valgrind）
# @tags:  ctf, reversing, solve, side-channel, instruction-count, bruteforce, perf, valgrind
# @deps:  perf（linux-tools）または valgrind
# @usage: python3 reversing/solve/sidechannel_brute.py ./chall --len 19 --prefix 'flag{' --success Correct
"""仕組み: 正しい文字が 1 つ増えると比較ループが 1 周多く回り、実行命令数が増える。
候補ごとの命令数を測り、最大（外れ値）の文字を採用して次の桁へ進む。

  --counter perf      高速。ベアメタル / VM で perf_event が使えること（sysctl kernel.perf_event_paranoid<=2）
  --counter valgrind  遅いがコンテナでも確実（valgrind --tool=lackey の guest instrs）

効かないケース: memcmp で一括比較 / 全文字比較してから判定 / 入力をハッシュ化してから比較
"""
import argparse
import re
import shutil
import string
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor


def run(binary, data, argv_mode, counter, success):
    args = [binary] + ([data.decode("latin-1")] if argv_mode else [])
    stdin = None if argv_mode else data + b"\n"
    if counter == "perf":
        cmd = ["perf", "stat", "-x", ",", "-e", "instructions:u", "--"] + args
        r = subprocess.run(cmd, input=stdin, capture_output=True, timeout=30)
        m = re.search(rb"^(\d+),", r.stderr, re.M)
    else:
        cmd = ["valgrind", "--tool=lackey", "--basic-counts=yes"] + args
        r = subprocess.run(cmd, input=stdin, capture_output=True, timeout=120)
        m = re.search(rb"guest instrs\s*:\s*([\d,]+)", r.stderr)
    if not m:
        sys.exit(f"error: 命令数を取得できません:\n{r.stderr.decode(errors='replace')[-800:]}")
    return int(m.group(1).replace(b",", b"")), bool(success and success.encode() in r.stdout)


def main():
    p = argparse.ArgumentParser(description="命令数サイドチャネル総当たり",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("binary")
    p.add_argument("--len", type=int, required=True, help="flag の長さ（strlen チェックがあるなら正確に）")
    p.add_argument("--prefix", default="", help="既知の先頭")
    p.add_argument("--charset", default=string.ascii_letters + string.digits + "_{}!@#$-.",
                   help="候補文字 (default: 英数字 + _{}!@#$-.)")
    p.add_argument("--pad", default="A", help="未確定部分を埋める文字 (default: A)")
    p.add_argument("--argv", action="store_true", help="入力を argv[1] で渡す（既定は stdin）")
    p.add_argument("--counter", choices=["perf", "valgrind"],
                   default="perf" if shutil.which("perf") else "valgrind")
    p.add_argument("--success", help="成功時の出力文字列（見つかったら終了）")
    p.add_argument("-j", "--jobs", type=int, default=8, help="並列数 (default: 8)")
    args = p.parse_args()

    known = args.prefix
    print(f"[*] counter={args.counter}  charset={len(args.charset)} chars")
    base, _ = run(args.binary, (known + args.pad * (args.len - len(known))).encode(), args.argv, args.counter, None)
    print(f"[*] baseline {base} instructions")
    while len(known) < args.len:
        cands = [known + ch + args.pad * (args.len - len(known) - 1) for ch in args.charset]
        with ThreadPoolExecutor(args.jobs) as ex:
            results = list(ex.map(lambda c: run(args.binary, c.encode(), args.argv, args.counter, args.success), cands))
        counts = [r[0] for r in results]
        for cand, (cnt, ok) in zip(cands, results):
            if ok:
                print(f"[+] success: {cand}")
                return
        best = max(range(len(counts)), key=lambda i: counts[i])
        others = sorted(counts)[len(counts) // 2]  # 中央値
        known += args.charset[best]
        print(f"[{len(known):>3}/{args.len}] {known:<{args.len}}  ({counts[best]} vs median {others}, "
              f"+{counts[best] - others})")
        if counts[best] == others:
            print("[-] 命令数に差が出ません。このプログラムにはサイドチャネルが効かない可能性")
            return
    print(f"[+] result: {known}")


if __name__ == "__main__":
    main()
