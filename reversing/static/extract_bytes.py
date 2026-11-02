#!/usr/bin/env python3
# @desc:  ELF/PE の仮想アドレス・シンボル名・ファイルオフセットからデータを抜き出し C 配列/Python リスト/u32 配列等に整形（暗号化テーブルの取り出し用）
# @tags:  ctf, reversing, static, extract, dump, va, offset, elf, pe, table
# @deps:  none
# @usage: python3 reversing/static/extract_bytes.py ./chall --sym enc_flag -f py
"""Ghidra / objdump で見つけた「比較対象の配列」をソルバに貼れる形で取り出す。

アドレスの基準:
  objdump / readelf / IDA         → そのまま --addr
  Ghidra（PIE ELF は 0x100000 起点） → --addr 0x101234 --base 0x100000
  gdb 実行中（PIE は 0x555555554000 起点）→ --addr 0x555555558010 --base 0x555555554000
"""
import argparse
import struct
import sys


def elf_info(data):
    bits64 = data[4] == 2
    e = "<" if data[5] == 1 else ">"
    if bits64:
        phoff, shoff = struct.unpack_from(e + "QQ", data, 0x20)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", data, 0x36)
    else:
        phoff, shoff = struct.unpack_from(e + "II", data, 0x1C)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", data, 0x2A)
    loads = []
    for i in range(phnum):
        off = phoff + i * phentsize
        if bits64:
            t, _, o, va, _, fs, ms, _ = struct.unpack_from(e + "IIQQQQQQ", data, off)
        else:
            t, o, va, _, fs, ms, _, _ = struct.unpack_from(e + "IIIIIIII", data, off)
        if t == 1:
            loads.append((va, o, fs, ms))
    syms = {}
    if shoff:
        secs = []
        for i in range(shnum):
            f = e + ("IIQQQQIIQQ" if bits64 else "IIIIIIIIII")
            secs.append(struct.unpack_from(f, data, shoff + i * shentsize))
        for name, typ, _, _, off, size, link, _, _, ent in secs:
            if typ not in (2, 11) or not ent:  # SYMTAB / DYNSYM
                continue
            stroff = secs[link][4]
            for so in range(off, off + size, ent):
                if bits64:
                    n, info, _, shndx, value, ssize = struct.unpack_from(e + "IBBHQQ", data, so)
                else:
                    n, value, ssize, info, _, shndx = struct.unpack_from(e + "IIIBBH", data, so)
                if n and shndx:
                    end = data.find(b"\0", stroff + n)
                    syms.setdefault(data[stroff + n:end].decode(errors="replace"), (value, ssize))
    return loads, syms, min((l[0] for l in loads), default=0) & ~0xFFF


def pe_info(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec, opt_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    is64 = struct.unpack_from("<H", data, opt)[0] == 0x20B
    base = struct.unpack_from("<Q" if is64 else "<I", data, opt + (24 if is64 else 28))[0]
    loads = []
    for i in range(nsec):
        vsize, rva, rsize, rptr = struct.unpack_from("<IIII", data, opt + opt_size + i * 40 + 8)
        loads.append((base + rva, rptr, rsize, max(vsize, rsize)))
    return loads, {}, base


def va2off(loads, va):
    for vaddr, off, filesz, memsz in loads:
        if vaddr <= va < vaddr + memsz:
            if va >= vaddr + filesz:
                sys.exit(f"error: {va:#x} は .bss 等（ファイル上にデータがない領域）です。実行時に gdb で dump してください")
            return off + va - vaddr
    sys.exit(f"error: {va:#x} はどのセグメント/セクションにも含まれません（--base の指定漏れ?）")


def fmt_out(b, fmt, be, name):
    e = ">" if be else "<"
    if fmt == "hex":
        return b.hex()
    if fmt == "bytes":
        return repr(b)
    if fmt == "py":
        return "[" + ", ".join(f"0x{x:02x}" for x in b) + "]"
    if fmt == "c":
        body = ",\n  ".join(", ".join(f"0x{x:02x}" for x in b[i:i + 12]) for i in range(0, len(b), 12))
        return f"unsigned char {name}[{len(b)}] = {{\n  {body}\n}};"
    if fmt in ("u16", "u32", "u64", "i32"):
        size = {"u16": 2, "u32": 4, "u64": 8, "i32": 4}[fmt]
        code = {"u16": "H", "u32": "I", "u64": "Q", "i32": "i"}[fmt]
        n = len(b) // size
        if len(b) % size:
            print(f"warning: 末尾 {len(b) % size} bytes は {fmt} に満たないため無視", file=sys.stderr)
        vals = struct.unpack(e + code * n, b[:n * size])
        return "[" + ", ".join(str(v) if fmt == "i32" else f"{v:#x}" for v in vals) + "]"
    if fmt == "xxd":
        return None
    raise ValueError(fmt)


def main():
    p = argparse.ArgumentParser(description="VA/シンボル/オフセットからデータ抽出",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n", 2)[2])
    p.add_argument("file")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-a", "--addr", type=lambda s: int(s, 0), help="仮想アドレス（例: 0x404070）")
    g.add_argument("-s", "--sym", help="シンボル名（ELF の非 stripped バイナリ。サイズも自動取得）")
    g.add_argument("--offset", type=lambda s: int(s, 0), help="ファイルオフセット（任意のファイル形式）")
    p.add_argument("-n", "--len", type=lambda s: int(s, 0), help="バイト数（--sym なら省略可）")
    p.add_argument("-f", "--format", default="xxd", choices=["xxd", "hex", "py", "bytes", "c", "u16", "u32", "u64", "i32", "raw"],
                   help="出力形式 (default: xxd)")
    p.add_argument("--be", action="store_true", help="u16/u32/u64 をビッグエンディアンで解釈")
    p.add_argument("--base", type=lambda s: int(s, 0), help="--addr が属するロードベース（Ghidra/gdb のアドレスを使う場合）")
    p.add_argument("-o", "--output", help="raw バイナリをファイルに保存")
    args = p.parse_args()

    data = open(args.file, "rb").read()
    if data[:4] == b"\x7fELF":
        loads, syms, link_base = elf_info(data)
    elif data[:2] == b"MZ":
        loads, syms, link_base = pe_info(data)
    else:
        loads, syms, link_base = [], {}, 0
        if args.offset is None:
            sys.exit("error: ELF/PE 以外は --offset のみ対応")

    length = args.len
    if args.sym:
        if args.sym not in syms:
            cands = [s for s in syms if args.sym in s][:10]
            sys.exit(f"error: シンボル {args.sym} がありません（stripped?）" + (f" 候補: {', '.join(cands)}" if cands else ""))
        va, size = syms[args.sym]
        length = length or size
        off = va2off(loads, va)
    elif args.addr is not None:
        va = args.addr - args.base + link_base if args.base is not None else args.addr
        off = va2off(loads, va)
    else:
        va, off = None, args.offset
    if not length:
        sys.exit("error: -n/--len でバイト数を指定してください")
    b = data[off:off + length]
    print(f"# {args.sym or ''} va={va:#x} " if va is not None else "# ", end="", file=sys.stderr)
    print(f"file_offset={off:#x} len={len(b)}", file=sys.stderr)

    if args.output or args.format == "raw":
        if args.output:
            open(args.output, "wb").write(b)
            print(f"[+] saved {args.output}", file=sys.stderr)
        else:
            sys.stdout.buffer.write(b)
        return
    out = fmt_out(b, args.format, args.be, args.sym or "data")
    if out is None:
        start = va if va is not None else off
        for i in range(0, len(b), 16):
            chunk = b[i:i + 16]
            asc = "".join(chr(x) if 0x20 <= x < 0x7F else "." for x in chunk)
            print(f"{start + i:08x}: {' '.join(f'{x:02x}' for x in chunk):<47}  {asc}")
    else:
        print(out)


if __name__ == "__main__":
    main()
