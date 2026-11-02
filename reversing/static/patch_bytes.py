#!/usr/bin/env python3
# @desc:  バイナリパッチ（VA/オフセット指定でバイト書換・NOP 埋め・条件分岐反転・常に jmp・即 return）とバイト列検索
# @tags:  ctf, reversing, static, patch, nop, jz, jnz, anti-debug, bypass, x86, arm64
# @deps:  none
# @usage: python3 reversing/static/patch_bytes.py ./chall --addr 0x4012a5 --flip -o ./chall.patched
"""よく使うパッチ（x86/x64。--nop と --ret は AArch64 にも対応）:
  --flip         jz ⇔ jnz など条件分岐を反転（74⇔75, 0f84⇔0f85 …）
  --jmp          条件分岐を無条件 jmp に（7x → eb / 0f8x rel32 → e9 rel32+1; 90）
  --nop N        N バイトを NOP（ptrace チェックの call を潰す等）
  --ret N        関数先頭を「return N」に（mov eax,N; ret）。チェック関数を常に成功させる
  --bytes HEX    任意バイトを書き込む（例: 'b8 01 00 00 00 c3'）
  --find HEX     バイト列を検索して offset / VA を表示（?? はワイルドカード）
"""
import argparse
import re
import shutil
import struct
import sys

AARCH64 = 183


def load_map(data):
    """[(vaddr, file_offset, filesz)] とアーキ番号を返す（ELF/PE）。それ以外は空"""
    if data[:4] == b"\x7fELF":
        bits64, e = data[4] == 2, "<" if data[5] == 1 else ">"
        machine = struct.unpack_from(e + "H", data, 18)[0]
        phoff = struct.unpack_from(e + ("Q" if bits64 else "I"), data, 0x20 if bits64 else 0x1C)[0]
        phentsize, phnum = struct.unpack_from(e + "HH", data, 0x36 if bits64 else 0x2A)
        segs = []
        for i in range(phnum):
            off = phoff + i * phentsize
            if bits64:
                t, _, o, va, _, fs, _, _ = struct.unpack_from(e + "IIQQQQQQ", data, off)
            else:
                t, o, va, _, fs, _, _, _ = struct.unpack_from(e + "IIIIIIII", data, off)
            if t == 1:
                segs.append((va, o, fs))
        return segs, machine
    if data[:2] == b"MZ":
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        machine, nsec = struct.unpack_from("<HH", data, pe + 4)
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        is64 = struct.unpack_from("<H", data, opt)[0] == 0x20B
        base = struct.unpack_from("<Q" if is64 else "<I", data, opt + (24 if is64 else 28))[0]
        segs = []
        for i in range(nsec):
            _, rva, rsize, rptr = struct.unpack_from("<IIII", data, opt + opt_size + i * 40 + 8)
            segs.append((base + rva, rptr, rsize))
        return segs, (AARCH64 if machine == 0xAA64 else machine)
    return [], None


def va2off(segs, va):
    for vaddr, off, size in segs:
        if vaddr <= va < vaddr + size:
            return off + va - vaddr
    sys.exit(f"error: {va:#x} はファイル上のどの領域にも含まれません")


def off2va(segs, off):
    for vaddr, o, size in segs:
        if o <= off < o + size:
            return vaddr + off - o
    return None


def build_patch(data, off, args, machine):
    if args.bytes:
        return bytes.fromhex(args.bytes.replace(" ", ""))
    if args.nop is not None:
        if machine == AARCH64:
            if args.nop % 4:
                sys.exit("error: AArch64 の --nop は 4 の倍数（命令単位）")
            return bytes.fromhex("1f2003d5") * (args.nop // 4)
        return b"\x90" * args.nop
    if args.ret is not None:
        if machine == AARCH64:  # mov w0, #imm16 ; ret
            return struct.pack("<II", 0x52800000 | ((args.ret & 0xFFFF) << 5), 0xD65F03C0)
        return b"\x31\xc0\xc3" if args.ret == 0 else b"\xb8" + struct.pack("<i", args.ret) + b"\xc3"
    b0, b1 = data[off], data[off + 1]
    if args.flip:
        if 0x70 <= b0 <= 0x7F:
            return bytes([b0 ^ 1])
        if b0 == 0x0F and 0x80 <= b1 <= 0x8F:
            return bytes([0x0F, b1 ^ 1])
        sys.exit(f"error: {off:#x} は条件分岐（7x / 0f 8x）ではありません: {data[off:off + 6].hex(' ')}")
    if args.jmp:
        if 0x70 <= b0 <= 0x7F:
            return b"\xeb"
        if b0 == 0x0F and 0x80 <= b1 <= 0x8F:  # 6 バイトの jcc rel32 → 5 バイトの jmp rel32 + nop
            rel = struct.unpack_from("<i", data, off + 2)[0]
            return b"\xe9" + struct.pack("<i", rel + 1) + b"\x90"
        sys.exit(f"error: {off:#x} は条件分岐（7x / 0f 8x）ではありません: {data[off:off + 6].hex(' ')}")
    sys.exit("error: パッチ内容（--bytes / --nop / --ret / --flip / --jmp）を指定してください")


def find(data, segs, pattern):
    parts = pattern.replace(" ", "")
    if len(parts) % 2:
        sys.exit("error: hex の桁数が奇数です")
    rx = b"".join(b"." if parts[i:i + 2] == "??" else re.escape(bytes.fromhex(parts[i:i + 2]))
                  for i in range(0, len(parts), 2))
    hits = [m.start() for m in re.finditer(rx, data, re.S)]
    for off in hits[:100]:
        va = off2va(segs, off)
        print(f"offset {off:#x}" + (f"  va {va:#x}" if va is not None else "") + f"  {data[off:off + 16].hex(' ')}")
    print(f"{len(hits)} hit(s)", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description="バイナリパッチ", formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n", 1)[1])
    p.add_argument("file")
    loc = p.add_mutually_exclusive_group()
    loc.add_argument("-a", "--addr", type=lambda s: int(s, 0), help="パッチする仮想アドレス（objdump/IDA 表記）")
    loc.add_argument("--offset", type=lambda s: int(s, 0), help="パッチするファイルオフセット")
    act = p.add_mutually_exclusive_group()
    act.add_argument("--bytes", help="書き込む hex")
    act.add_argument("--nop", type=int, metavar="N", help="N バイト NOP")
    act.add_argument("--ret", type=lambda s: int(s, 0), metavar="N", help="関数先頭を return N に")
    act.add_argument("--flip", action="store_true", help="条件分岐を反転")
    act.add_argument("--jmp", action="store_true", help="条件分岐を無条件 jmp に")
    act.add_argument("--find", metavar="HEX", help="バイト列検索（パッチはしない）")
    p.add_argument("--base", type=lambda s: int(s, 0), default=None,
                   help="--addr のロードベース（Ghidra の PIE は 0x100000）。ファイル上のベースに換算する")
    p.add_argument("-o", "--output", help="出力先 (default: <file>.patched)。元ファイルと同じパスなら上書き")
    args = p.parse_args()

    data = bytearray(open(args.file, "rb").read())
    segs, machine = load_map(data)
    if args.find:
        find(bytes(data), segs, args.find)
        return
    if args.addr is None and args.offset is None:
        sys.exit("error: --addr か --offset を指定してください")
    if args.addr is not None:
        addr = args.addr
        if args.base is not None:
            addr = addr - args.base + (min(s[0] for s in segs) & ~0xFFF)
        off = va2off(segs, addr)
    else:
        off = args.offset
    patch = build_patch(data, off, args, machine)
    before = bytes(data[off:off + len(patch)])
    data[off:off + len(patch)] = patch
    out = args.output or args.file + ".patched"
    if out != args.file:
        shutil.copyfile(args.file, out)
        shutil.copymode(args.file, out)
    with open(out, "r+b") as f:
        f.write(data)
    print(f"offset {off:#x}: {before.hex(' ')}  ->  {patch.hex(' ')}")
    print(f"[+] {out}")
    if data[:4] == b"\xcf\xfa\xed\xfe":
        print("note: macOS の Mach-O は署名が壊れるので `codesign -f -s - <file>` で再署名")


if __name__ == "__main__":
    main()
