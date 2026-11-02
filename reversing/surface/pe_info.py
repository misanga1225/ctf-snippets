#!/usr/bin/env python3
# @desc:  PE (exe/dll) のヘッダ・保護機構・セクション（エントロピー付き）・インポート/エクスポート・TLS・PDB パス・オーバーレイを表示
# @tags:  ctf, reversing, surface, pe, windows, exe, dll, imports, dotnet
# @deps:  none
# @usage: python3 reversing/surface/pe_info.py ./chall.exe [--imports] [--exports]
"""pefile なしで PE の要点を見る。怪しい API（アンチデバッグ・インジェクション・暗号）に印を付ける。"""
import argparse
import datetime
import math
import struct
import sys
from collections import Counter

MACHINES = {0x14C: "x86 (i386)", 0x8664: "x86-64 (AMD64)", 0x1C0: "ARM", 0x1C4: "ARM Thumb-2", 0xAA64: "ARM64"}
SUBSYSTEMS = {1: "Native (ドライバ)", 2: "GUI", 3: "Console (CUI)", 10: "EFI Application", 11: "EFI Boot Driver"}
DLLCHAR = {0x0020: "HIGH_ENTROPY_VA", 0x0040: "ASLR (DYNAMIC_BASE)", 0x0100: "DEP (NX_COMPAT)",
           0x0400: "NO_SEH", 0x4000: "CFG (GUARD_CF)"}
PACKER_SECTIONS = {"UPX0": "UPX", "UPX1": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".vmp0": "VMProtect",
                   ".vmp1": "VMProtect", ".themida": "Themida", ".winlice": "Themida", ".enigma1": "Enigma",
                   ".petite": "Petite", ".MPRESS1": "MPRESS", ".nsp0": "NsPack", "pebundle": "PEBundle"}
SUSPICIOUS_API = {
    "anti-debug": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                   "OutputDebugString", "NtSetInformationThread", "GetTickCount", "QueryPerformanceCounter",
                   "FindWindow", "BlockInput"],
    "injection": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
                  "SetThreadContext", "QueueUserAPC", "SetWindowsHookEx"],
    "dynamic-resolve": ["LoadLibrary", "GetProcAddress", "LdrLoadDll"],
    "self-modify": ["VirtualProtect", "VirtualAlloc"],
    "crypto": ["CryptAcquireContext", "CryptDecrypt", "CryptEncrypt", "CryptCreateHash", "BCryptDecrypt",
               "BCryptEncrypt", "CryptStringToBinary"],
    "network": ["WSAStartup", "socket", "connect", "InternetOpen", "InternetReadFile", "URLDownloadToFile",
                "WinHttpOpen", "HttpSendRequest"],
}


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return max(0.0, -sum(c / n * math.log2(c / n) for c in Counter(b).values()))


def cstr(data: bytes, off: int, limit: int = 512) -> str:
    end = data.find(b"\0", off, off + limit)
    return data[off:end if end >= 0 else off + limit].decode(errors="replace")


class PE:
    def __init__(self, data: bytes):
        if data[:2] != b"MZ":
            raise ValueError("PE ではありません（先頭が MZ でない）")
        self.data = data
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("PE シグネチャが見つかりません（MS-DOS 実行ファイル?）")
        (self.machine, nsec, self.timestamp, symptr, nsyms, opt_size, self.characteristics) = \
            struct.unpack_from("<HHIIIHH", data, pe + 4)
        # COFF シンボルテーブル（MinGW の未 strip バイナリに残る）。長いセクション名 "/4" はこの文字列表を参照
        self.coff_strtab = symptr + nsyms * 18 if symptr and symptr + nsyms * 18 + 4 <= len(data) else None
        self.coff_end = None
        if self.coff_strtab is not None:
            self.coff_end = self.coff_strtab + struct.unpack_from("<I", data, self.coff_strtab)[0]
        opt = pe + 24
        self.magic = struct.unpack_from("<H", data, opt)[0]
        self.is64 = self.magic == 0x20B
        self.entry = struct.unpack_from("<I", data, opt + 16)[0]
        self.image_base = struct.unpack_from("<Q" if self.is64 else "<I", data, opt + (24 if self.is64 else 28))[0]
        self.subsystem, self.dllchar = struct.unpack_from("<HH", data, opt + 68)
        ndirs_off = opt + (108 if self.is64 else 92)
        ndirs = struct.unpack_from("<I", data, ndirs_off)[0]
        self.dirs = [struct.unpack_from("<II", data, ndirs_off + 4 + i * 8) for i in range(min(ndirs, 16))]
        self.sections = []
        sec = opt + opt_size
        for i in range(nsec):
            name, vsize, va, rsize, rptr = struct.unpack_from("<8sIIII", data, sec + i * 40)
            chars = struct.unpack_from("<I", data, sec + i * 40 + 36)[0]
            name = name.rstrip(b"\0").decode(errors="replace")
            if name.startswith("/") and name[1:].isdigit() and self.coff_strtab is not None:
                name = cstr(data, self.coff_strtab + int(name[1:]))
            self.sections.append({"name": name, "vsize": vsize, "va": va,
                                  "rsize": rsize, "rptr": rptr, "chars": chars})

    def rva2off(self, rva):
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
                off = rva - s["va"] + s["rptr"]
                return off if off < len(self.data) else None
        return rva if rva < len(self.data) else None

    def dir(self, idx):
        return self.dirs[idx] if idx < len(self.dirs) else (0, 0)

    def imports(self):
        rva, size = self.dir(1)
        res = {}
        off = self.rva2off(rva) if rva else None
        while off is not None and off + 20 <= len(self.data):
            oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", self.data, off)
            if not (oft or name_rva or ft):
                break
            dll = cstr(self.data, self.rva2off(name_rva) or 0)
            funcs = []
            toff = self.rva2off(oft or ft)
            fmt, step, flag = ("<Q", 8, 1 << 63) if self.is64 else ("<I", 4, 1 << 31)
            while toff is not None and toff + step <= len(self.data):
                v = struct.unpack_from(fmt, self.data, toff)[0]
                if not v:
                    break
                if v & flag:
                    funcs.append(f"ordinal#{v & 0xFFFF}")
                else:
                    hint = self.rva2off(v & 0x7FFFFFFF)
                    funcs.append(cstr(self.data, hint + 2) if hint is not None else "?")
                toff += step
            res[dll] = funcs
            off += 20
        return res

    def exports(self):
        rva, _ = self.dir(0)
        off = self.rva2off(rva) if rva else None
        if off is None:
            return None, []
        name_rva, base, nfunc, nnames, afuncs, anames, aords = struct.unpack_from("<IIIIIII", self.data, off + 12)
        dll = cstr(self.data, self.rva2off(name_rva) or 0)
        out = []
        for i in range(nnames):
            n_off = self.rva2off(anames + i * 4)
            o_off = self.rva2off(aords + i * 2)
            if n_off is None or o_off is None:
                break
            ordinal = struct.unpack_from("<H", self.data, o_off)[0]
            f_off = self.rva2off(afuncs + ordinal * 4)
            frva = struct.unpack_from("<I", self.data, f_off)[0] if f_off is not None else 0
            out.append((ordinal + base, frva, cstr(self.data, self.rva2off(struct.unpack_from("<I", self.data, n_off)[0]) or 0)))
        return dll, out

    def pdb_path(self):
        rva, size = self.dir(6)
        off = self.rva2off(rva) if rva else None
        if off is None:
            return None
        for i in range(size // 28):
            typ, _, _, ptr = struct.unpack_from("<IIII", self.data, off + i * 28 + 12)
            if typ == 2 and self.data[ptr:ptr + 4] == b"RSDS":
                return cstr(self.data, ptr + 24)
        return None

    def tls_callbacks(self):
        rva, _ = self.dir(9)
        off = self.rva2off(rva) if rva else None
        if off is None:
            return []
        fmt, step = ("<Q", 8) if self.is64 else ("<I", 4)
        cb_va = struct.unpack_from(fmt, self.data, off + step * 3)[0]  # AddressOfCallBacks (VA)
        cbs, coff = [], self.rva2off(cb_va - self.image_base) if cb_va else None
        while coff is not None and len(cbs) < 32:
            v = struct.unpack_from(fmt, self.data, coff)[0]
            if not v:
                break
            cbs.append(v)
            coff += step
        return cbs

    def overlay(self):
        end = max((s["rptr"] + s["rsize"] for s in self.sections if s["rsize"]), default=0)
        return end, len(self.data) - end


def main():
    p = argparse.ArgumentParser(description="PE 情報表示（pefile / PE-bear / DIE の簡易版）")
    p.add_argument("file")
    p.add_argument("-i", "--imports", action="store_true", help="インポート関数を全て表示（既定は怪しい API のみ）")
    p.add_argument("-e", "--exports", action="store_true", help="エクスポート関数を表示（DLL 解析向け）")
    args = p.parse_args()

    data = open(args.file, "rb").read()
    try:
        pe = PE(data)
    except (ValueError, struct.error) as e:
        sys.exit(f"error: {e}")

    ts = datetime.datetime.fromtimestamp(pe.timestamp, datetime.timezone.utc)
    print(f"== {args.file}")
    print(f"  format    : {'PE32+ (64bit)' if pe.is64 else 'PE32 (32bit)'}{' DLL' if pe.characteristics & 0x2000 else ''}")
    print(f"  machine   : {MACHINES.get(pe.machine, hex(pe.machine))}")
    print(f"  subsystem : {SUBSYSTEMS.get(pe.subsystem, pe.subsystem)}")
    print(f"  imagebase : {pe.image_base:#x}")
    print(f"  entry     : RVA {pe.entry:#x}  (VA {pe.image_base + pe.entry:#x})")
    print(f"  timestamp : {ts:%Y-%m-%d %H:%M:%S} UTC{'  (偽装/再現ビルドの可能性)' if ts.year < 2000 or ts.year > 2035 else ''}")
    flags = [n for bit, n in DLLCHAR.items() if pe.dllchar & bit]
    print(f"  security  : {', '.join(flags) or 'なし'}")
    pdb = pe.pdb_path()
    if pdb:
        print(f"  pdb path  : {pdb}   ← 作者の環境・プロジェクト名がわかることがある")

    hints = []
    if pe.dir(14)[0]:
        hints.append(".NET アセンブリ（CLR ヘッダあり）→ ILSpy / dnSpyEx / ilspycmd で C# に戻せる")
    cbs = pe.tls_callbacks()
    if cbs:
        hints.append(f"TLS コールバック {len(cbs)} 個 ({', '.join(hex(v) for v in cbs)}) → エントリポイントより先に実行される"
                     "（アンチデバッグの定番。MinGW は標準で 1〜2 個持つ）")
    for s in pe.sections:
        if s["name"] in PACKER_SECTIONS:
            hints.append(f"セクション名 {s['name']} → {PACKER_SECTIONS[s['name']]} でパックされている可能性")
    if b"UPX!" in data[:0x1000] and not any("UPX" in h for h in hints):
        hints.append("UPX シグネチャあり → upx -d で展開")
    if b"PyInstaller" in data or b"_MEIPASS" in data:
        hints.append("PyInstaller → pyinstxtractor で展開 → static/pyc_tool.py")
    if b"AutoIt" in data:
        hints.append("AutoIt スクリプト → AutoIt-Ripper で抽出")
    if b"Go build ID" in data:
        hints.append("Go バイナリ → GoReSym で関数名復元")
    end, ov = pe.overlay()
    if ov > 0 and pe.coff_strtab is not None and end <= pe.coff_strtab and pe.coff_end >= len(data) - 16:
        hints.append(f"末尾 {ov} bytes は COFF シンボルテーブル（未 strip の MinGW ビルド → 関数名が残っている）")
    elif ov > 0:
        hints.append(f"オーバーレイ {ov} bytes（offset {end:#x}〜）→ 追加データ/インストーラ/埋め込みファイル。"
                     f"embedded_scan.py で確認")
    if hints:
        print("\n== hints")
        for h in hints:
            print(f"  [+] {h}")

    print("\n== sections  (R/W/X / entropy > 7.0 は圧縮・暗号化の疑い)")
    print(f"  {'name':<16}{'VA':>10}{'vsize':>10}{'rawptr':>10}{'rawsize':>10}  flg  entropy")
    for s in pe.sections:
        c = s["chars"]
        fl = ("R" if c & 0x40000000 else "-") + ("W" if c & 0x80000000 else "-") + ("X" if c & 0x20000000 else "-")
        ent = entropy(data[s["rptr"]:s["rptr"] + s["rsize"]])
        mark = []
        if ent > 7.0 and s["rsize"] > 256:
            mark.append("high")
        if c & 0x80000000 and c & 0x20000000:
            mark.append("W+X")
        if s["rsize"] == 0 and s["vsize"] > 0x1000:
            mark.append("raw=0（実行時に展開?）")
        print(f"  {s['name']:<16}{s['va']:>#10x}{s['vsize']:>#10x}{s['rptr']:>#10x}{s['rsize']:>#10x}  {fl}  "
              f"{ent:5.2f}{'  <-- ' + ', '.join(mark) if mark else ''}")

    imps = pe.imports()
    print(f"\n== imports ({len(imps)} DLL, {sum(map(len, imps.values()))} 関数)")
    for dll, funcs in imps.items():
        print(f"  {dll}" + (f": {', '.join(funcs)}" if args.imports else f" ({len(funcs)})"))
    found = []
    for cat, apis in SUSPICIOUS_API.items():
        hit = sorted({f for fs in imps.values() for f in fs for a in apis if f.startswith(a)})
        if hit:
            found.append((cat, hit))
    if found:
        print("\n== 注目 API")
        for cat, hit in found:
            print(f"  {cat:<16}: {', '.join(hit)}")

    if args.exports:
        dll, exps = pe.exports()
        print(f"\n== exports ({dll or '-'}: {len(exps)})")
        for ordinal, rva, name in exps:
            print(f"  #{ordinal:<5} RVA {rva:#010x}  {name}")


if __name__ == "__main__":
    main()
