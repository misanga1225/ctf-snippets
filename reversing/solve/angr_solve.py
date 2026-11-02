#!/usr/bin/env python3
# @desc:  angr のシンボリック実行で「成功メッセージに到達する入力」を自動探索（stdin / argv 入力、文字列 or アドレスで find/avoid 指定）
# @tags:  ctf, reversing, solve, angr, symbolic-execution, crackme, keygen
# @deps:  angr（pip install angr。Python 3.10〜3.12 推奨）
# @usage: python3 reversing/solve/angr_solve.py ./chall --find Correct --avoid Wrong --len 32
"""典型的な crackme（入力を変換して比較 → Correct / Wrong を表示）はこれだけで解けることが多い。

アドレスで指定する場合の注意（PIE バイナリ）:
  angr は PIE を 0x400000 にロードする。Ghidra のアドレス（0x100000 起点）をそのまま使いたいなら --base 0x100000
  objdump のアドレス（0 起点）なら --base 0

解けないとき:
  - 入力長 --len を正しく（strlen チェックがあるなら必ず一致させる）
  - --printable / --prefix 'flag{' で探索空間を絞る
  - 状態爆発 → --avoid を増やす / 判定関数 check(char *s) の先頭から始める（--start 0x... --find <return 1 の地点>）
  - 暗号ハッシュ（SHA 等）を通す処理は原理的に解けない → 総当たり or 別の弱点を探す
"""
import argparse
import logging
import sys
import time

try:
    import angr
except ImportError:
    sys.exit("error: angr がありません。pip install angr（venv 推奨）")
try:
    import claripy  # angr 9.x
except ImportError:
    from angr import claripy  # angr 10 以降は angr に同梱


def addr_or_str(v):
    try:
        return int(v, 0)
    except ValueError:
        return v.encode()


def make_cond(targets):
    addrs = [t for t in targets if isinstance(t, int)]
    strs = [t for t in targets if isinstance(t, bytes)]

    def cond(state):
        if state.addr in addrs:
            return True
        if strs:
            out = state.posix.dumps(1)
            return any(s in out for s in strs)
        return False
    return cond if targets else None


def main():
    p = argparse.ArgumentParser(description="angr 自動ソルバ", formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n", 2)[2])
    p.add_argument("binary")
    p.add_argument("--find", action="append", type=addr_or_str, required=True,
                   help="到達したい出力文字列 or アドレス（複数可）")
    p.add_argument("--avoid", action="append", type=addr_or_str, default=[],
                   help="避けたい出力文字列 or アドレス（複数可）")
    p.add_argument("--len", type=int, default=32, help="入力の長さ (default: 32)")
    p.add_argument("--argv", action="store_true", help="入力を argv[1] として与える（既定は stdin）")
    p.add_argument("--printable", action="store_true", help="入力を印字可能文字に制約")
    p.add_argument("--prefix", default="", help="既知の先頭（例: 'flag{'）")
    p.add_argument("--charset", help="使う文字を限定（例: 0123456789abcdef）")
    p.add_argument("--newline", action="store_true",
                   help="stdin 入力の末尾に改行を付ける（既定は付けずに EOF。angr の fgets/strcspn は改行付きだと解けないことがある）")
    p.add_argument("--base", type=lambda s: int(s, 0), help="PIE のロードベース（Ghidra 準拠なら 0x100000）")
    p.add_argument("--start", type=lambda s: int(s, 0), help="この関数アドレスから実行（blank_state）。入力は第 1 引数（rdi / x0 等）にポインタで渡す")
    p.add_argument("--veritesting", action="store_true", help="Veritesting で状態爆発を抑える（遅くなることもある）")
    p.add_argument("--timeout", type=int, default=600, help="探索の打ち切り秒 (default: 600)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.getLogger("angr").setLevel(logging.INFO if args.verbose else logging.ERROR)
    main_opts = {"base_addr": args.base} if args.base is not None else {}
    proj = angr.Project(args.binary, auto_load_libs=False, main_opts=main_opts)
    print(f"[*] {proj.arch.name}, base {proj.loader.main_object.min_addr:#x}, entry {proj.entry:#x}")

    chars = [claripy.BVS(f"c{i}", 8) for i in range(args.len)]
    sym = claripy.Concat(*chars)
    opts = {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}

    if args.start is not None:
        state = proj.factory.blank_state(addr=args.start, add_options=opts)
        buf = 0x7FFF0000
        state.memory.store(buf, claripy.Concat(sym, claripy.BVV(0, 8)))
        reg = proj.factory.cc().ARG_REGS[0]  # x86-64: rdi / AArch64: x0 / ARM: r0 ...
        setattr(state.regs, reg, buf)
    elif args.argv:
        state = proj.factory.full_init_state(args=[args.binary, sym], add_options=opts)
    else:
        data = claripy.Concat(sym, claripy.BVV(b"\n")) if args.newline else sym
        state = proj.factory.full_init_state(args=[args.binary], add_options=opts,
                                             stdin=angr.SimFileStream(name="stdin", content=data, has_end=True))

    for i, c in enumerate(chars):
        if i < len(args.prefix):
            state.solver.add(c == ord(args.prefix[i]))
        elif args.charset:
            state.solver.add(claripy.Or(*[c == ord(x) for x in args.charset]))
        elif args.printable:
            state.solver.add(c >= 0x20, c <= 0x7E)
        else:
            state.solver.add(c != 0, c != 0x0A)

    simgr = proj.factory.simgr(state, veritesting=args.veritesting)
    simgr.use_technique(angr.exploration_techniques.Timeout(timeout=args.timeout))
    t0 = time.time()
    print("[*] exploring ...")
    simgr.explore(find=make_cond(args.find), avoid=make_cond(args.avoid))
    print(f"[*] {time.time() - t0:.1f}s  {simgr}")

    if not simgr.found:
        sys.exit("[-] 見つかりませんでした（--len / --avoid / --printable を見直す。docstring の『解けないとき』参照）")
    s = simgr.found[0]
    ans = s.solver.eval(sym, cast_to=bytes)
    print(f"[+] input : {ans!r}")
    print(f"[+] stdout: {s.posix.dumps(1)!r}")


if __name__ == "__main__":
    main()
