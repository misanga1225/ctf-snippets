#!/usr/bin/env python3
# @desc:  ELF のヘッダ・保護機構（checksec 相当）・セクション（エントロピー付き）・依存ライブラリ・シンボルを表示
# @tags:  ctf, reversing, surface, elf, checksec, sections, symbols, linux
# @deps:  none
# @usage: python3 reversing/surface/elf_info.py ./chall [--symbols [main]] [--segments] [--json]
"""readelf / checksec / nm の要点を Python 標準ライブラリだけで出す。macOS でも ELF を解析できる。"""
import argparse
import json
import math
import struct
import sys
from collections import Counter

MACHINES = {2: "SPARC", 3: "x86 (i386)", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 40: "ARM (32bit)",
            43: "SPARCv9", 62: "x86-64", 183: "AArch64", 243: "RISC-V", 258: "LoongArch"}
TYPES = {1: "REL (オブジェクトファイル)", 2: "EXEC (実行ファイル)", 3: "DYN (PIE / 共有ライブラリ)", 4: "CORE"}
PT = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 7: "TLS",
      0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO", 0x6474E553: "GNU_PROPERTY"}
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK, PT_GNU_RELRO = 1, 2, 3, 0x6474E551, 0x6474E552
DT_NEEDED, DT_STRTAB, DT_RPATH, DT_BIND_NOW, DT_RUNPATH, DT_FLAGS, DT_FLAGS_1 = 1, 5, 15, 24, 29, 30, 0x6FFFFFFB
SHT_SYMTAB, SHT_DYNSYM, SHT_NOBITS = 2, 11, 8
STT = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 6: "TLS", 10: "IFUNC"}


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return max(0.0, -sum(c / n * math.log2(c / n) for c in Counter(b).values()))


def cstr(data: bytes, off: int) -> str:
    end = data.find(b"\0", off)
    return data[off:end if end >= 0 else len(data)].decode(errors="replace")


class ELF:
    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF":
            raise ValueError("ELF ではありません（先頭が 7f 45 4c 46 でない）")
        self.data = data
        self.bits = 64 if data[4] == 2 else 32
        self.e = "<" if data[5] == 1 else ">"
        hdr = "HHIQQQIHHHHHH" if self.bits == 64 else "HHIIIIIHHHHHH"
        (self.type, self.machine, _, self.entry, phoff, shoff, self.flags, _,
         phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(self.e + hdr, data, 16)
        self.segments = [self._phdr(phoff + i * phentsize) for i in range(phnum)] if phoff else []
        self.sections = []
        if shoff and shoff + shnum * shentsize <= len(data):  # sstrip 等でセクションヘッダが消されている場合あり
            self.sections = [self._shdr(shoff + i * shentsize) for i in range(shnum)]
            if 0 < shstrndx < len(self.sections):
                strtab = self.sections[shstrndx]["offset"]
                for s in self.sections:
                    s["name"] = cstr(data, strtab + s["name_off"])

    def _phdr(self, off):
        if self.bits == 64:
            t, fl, o, va, _, fs, ms, al = struct.unpack_from(self.e + "IIQQQQQQ", self.data, off)
        else:
            t, o, va, _, fs, ms, fl, al = struct.unpack_from(self.e + "IIIIIIII", self.data, off)
        return {"type": t, "flags": fl, "offset": o, "vaddr": va, "filesz": fs, "memsz": ms}

    def _shdr(self, off):
        f = "IIQQQQIIQQ" if self.bits == 64 else "IIIIIIIIII"
        n, t, fl, addr, o, size, link, info, al, es = struct.unpack_from(self.e + f, self.data, off)
        return {"name_off": n, "name": "", "type": t, "flags": fl, "addr": addr, "offset": o,
                "size": size, "link": link, "entsize": es}

    def va2off(self, va):
        for s in self.segments:
            if s["type"] == PT_LOAD and s["vaddr"] <= va < s["vaddr"] + s["filesz"]:
                return va - s["vaddr"] + s["offset"]
        return None

    def section(self, name):
        return next((s for s in self.sections if s["name"] == name), None)

    def segment(self, ptype):
        return next((s for s in self.segments if s["type"] == ptype), None)

    def interp(self):
        s = self.segment(PT_INTERP)
        return cstr(self.data, s["offset"]) if s else None

    def dynamic(self):
        seg = self.segment(PT_DYNAMIC)
        if not seg:
            return []
        f, size = ("qQ", 16) if self.bits == 64 else ("iI", 8)
        out = []
        for off in range(seg["offset"], seg["offset"] + seg["filesz"], size):
            tag, val = struct.unpack_from(self.e + f, self.data, off)
            if tag == 0:
                break
            out.append((tag, val))
        return out

    def dyn_strings(self):
        """DT_NEEDED / RPATH / RUNPATH を文字列に解決"""
        dyn = self.dynamic()
        strtab = next((v for t, v in dyn if t == DT_STRTAB), None)
        base = self.va2off(strtab) if strtab is not None else None
        if base is None and self.section(".dynstr"):
            base = self.section(".dynstr")["offset"]
        res = {"needed": [], "rpath": [], "runpath": []}
        if base is None:
            return res
        for t, v in dyn:
            key = {DT_NEEDED: "needed", DT_RPATH: "rpath", DT_RUNPATH: "runpath"}.get(t)
            if key:
                res[key].append(cstr(self.data, base + v))
        return res

    def symbols(self):
        syms = []
        for sec in self.sections:
            if sec["type"] not in (SHT_SYMTAB, SHT_DYNSYM) or not sec["entsize"]:
                continue
            strtab = self.sections[sec["link"]]["offset"]
            for off in range(sec["offset"], sec["offset"] + sec["size"], sec["entsize"]):
                if self.bits == 64:
                    name, info, _, shndx, value, size = struct.unpack_from(self.e + "IBBHQQ", self.data, off)
                else:
                    name, value, size, info, _, shndx = struct.unpack_from(self.e + "IIIBBH", self.data, off)
                if not name:
                    continue
                syms.append({"name": cstr(self.data, strtab + name), "value": value, "size": size,
                             "type": STT.get(info & 0xF, str(info & 0xF)), "bind": info >> 4,
                             "defined": shndx != 0, "table": ".symtab" if sec["type"] == SHT_SYMTAB else ".dynsym"})
        return syms

    def protections(self):
        dyn = dict(self.dynamic())
        names = {s["name"] for s in self.symbols()}
        stack = self.segment(PT_GNU_STACK)
        bind_now = DT_BIND_NOW in dyn or dyn.get(DT_FLAGS, 0) & 0x8 or dyn.get(DT_FLAGS_1, 0) & 0x1
        if self.segment(PT_GNU_RELRO):
            relro = "Full RELRO（GOT 書き換え不可）" if bind_now else "Partial RELRO（GOT 書き換え可）"
        else:
            relro = "No RELRO"
        if self.type == 3:
            pie = "PIE 有効" if self.interp() or dyn.get(DT_FLAGS_1, 0) & 0x08000000 else "共有ライブラリ (DSO)"
        else:
            pie = "No PIE（アドレス固定）" if self.type == 2 else "-"
        fortify = sorted(n for n in names if n.startswith("__") and n.endswith("_chk") and n != "__stack_chk_fail")
        return {
            "relro": relro,
            "canary": "あり" if names & {"__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie"} else "なし",
            "nx": "NX 有効" if stack and not stack["flags"] & 1 else "NX 無効（スタック実行可）",
            "pie": pie,
            "fortify": f"あり ({', '.join(fortify[:4])}{' ...' if len(fortify) > 4 else ''})" if fortify else "なし",
            "stripped": "No（シンボルあり）" if self.section(".symtab") else "Yes（.symtab なし）",
            "linking": "dynamic" if self.interp() else "static（libc 関数も本体に含まれる）",
        }


def sec_flags(f):
    return ("W" if f & 1 else "-") + ("A" if f & 2 else "-") + ("X" if f & 4 else "-")


def main():
    p = argparse.ArgumentParser(description="ELF 情報表示（readelf/checksec/nm 簡易版）")
    p.add_argument("file")
    p.add_argument("-s", "--symbols", nargs="?", const="", metavar="FILTER",
                   help="定義済み関数/変数シンボルを表示（FILTER で部分一致絞り込み）")
    p.add_argument("-l", "--segments", action="store_true", help="プログラムヘッダ（セグメント）も表示")
    p.add_argument("--json", action="store_true", help="JSON で出力")
    args = p.parse_args()

    data = open(args.file, "rb").read()
    try:
        elf = ELF(data)
    except ValueError as e:
        sys.exit(f"error: {e}")
    prot = elf.protections()
    dyns = elf.dyn_strings()
    hints = []
    names = {s["name"] for s in elf.sections}
    if names & {".gopclntab", ".note.go.buildid"} or b"Go build ID" in data:
        hints.append("Go バイナリ（GoReSym / redress で関数名復元、Ghidra 11+ は Go を標準サポート）")
    if b"/rustc/" in data or b"rust_panic" in data:
        hints.append("Rust バイナリ（core::panicking などのノイズが多い。main は <crate>::main を探す）")
    if b"UPX!" in data:
        hints.append("UPX パック（upx -d で展開）")
    if not elf.sections:
        hints.append("セクションヘッダなし（sstrip / パック済みの可能性。セグメントで解析）")

    if args.json:
        out = {"bits": elf.bits, "endian": "little" if elf.e == "<" else "big",
               "machine": MACHINES.get(elf.machine, elf.machine), "type": TYPES.get(elf.type, elf.type),
               "entry": hex(elf.entry), "interp": elf.interp(), **dyns, "protections": prot, "hints": hints,
               "sections": [{k: s[k] for k in ("name", "addr", "offset", "size")} for s in elf.sections]}
        if args.symbols is not None:
            out["symbols"] = [s for s in elf.symbols() if s["defined"] and args.symbols in s["name"]]
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return

    print(f"== {args.file}")
    print(f"  class     : ELF{elf.bits} {'little' if elf.e == '<' else 'big'}-endian")
    print(f"  machine   : {MACHINES.get(elf.machine, elf.machine)}")
    print(f"  type      : {TYPES.get(elf.type, elf.type)}")
    print(f"  entry     : {elf.entry:#x}")
    print(f"  interp    : {elf.interp() or '-'}")
    print(f"  needed    : {', '.join(dyns['needed']) or '-'}")
    if dyns["rpath"] or dyns["runpath"]:
        print(f"  rpath     : {', '.join(dyns['rpath'] + dyns['runpath'])}")
    print("\n== protections (checksec)")
    for k, v in prot.items():
        print(f"  {k:<9} : {v}")
    if hints:
        print("\n== hints")
        for h in hints:
            print(f"  [+] {h}")

    if elf.sections:
        print("\n== sections  (flags: W=書込 A=ロード X=実行 / entropy > 7.0 は圧縮・暗号化の疑い)")
        print(f"  {'name':<22}{'addr':>14}{'offset':>10}{'size':>10}  flg  entropy")
        for s in elf.sections:
            if not s["name"]:
                continue
            body = b"" if s["type"] == SHT_NOBITS else data[s["offset"]:s["offset"] + s["size"]]
            ent = entropy(body)
            mark = "  <-- high" if ent > 7.0 and len(body) > 256 else ""
            print(f"  {s['name']:<22}{s['addr']:>#14x}{s['offset']:>#10x}{s['size']:>#10x}  {sec_flags(s['flags'])}  "
                  f"{ent:5.2f}{mark}")

    if args.segments:
        print("\n== segments")
        print(f"  {'type':<14}{'offset':>10}{'vaddr':>14}{'filesz':>10}{'memsz':>10}  flg")
        for s in elf.segments:
            fl = ("R" if s["flags"] & 4 else "-") + ("W" if s["flags"] & 2 else "-") + ("X" if s["flags"] & 1 else "-")
            print(f"  {PT.get(s['type'], hex(s['type'])):<14}{s['offset']:>#10x}{s['vaddr']:>#14x}"
                  f"{s['filesz']:>#10x}{s['memsz']:>#10x}  {fl}")

    if args.symbols is not None:
        syms = sorted({(s["value"], s["name"]): s for s in elf.symbols()
                       if s["defined"] and s["type"] in ("FUNC", "OBJECT", "IFUNC") and args.symbols in s["name"]}
                      .values(), key=lambda s: s["value"])
        print(f"\n== symbols ({len(syms)})")
        for s in syms:
            print(f"  {s['value']:#014x}  {s['size']:>6}  {s['type']:<6} {s['name']}")
        undef = sorted({s["name"].split("@")[0] for s in elf.symbols() if not s["defined"] and s["type"] == "FUNC"})
        if undef and not args.symbols:
            print(f"\n== imported functions ({len(undef)})")
            print("  " + ", ".join(undef))


if __name__ == "__main__":
    main()
