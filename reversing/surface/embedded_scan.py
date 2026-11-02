#!/usr/bin/env python3
# @desc:  バイナリ内に埋め込まれたファイル（ELF/PE/ZIP/PNG/gzip/zlib 等）をシグネチャで検出・切り出し（binwalk 簡易版）
# @tags:  ctf, reversing, surface, binwalk, carve, embedded, zlib, forensics
# @deps:  none
# @usage: python3 reversing/surface/embedded_scan.py ./chall [-x ./carved]
"""binwalk がない環境向け。zlib/gzip は実際に展開できたものだけを報告するので誤検出が少ない。"""
import argparse
import os
import struct
import sys
import zlib

SIGS = [  # (magic, 名前, 拡張子)
    (b"\x7fELF", "ELF", "elf"),
    (b"MZ", "PE (MZ)", "exe"),
    (b"\x89PNG\r\n\x1a\n", "PNG", "png"),
    (b"\xff\xd8\xff", "JPEG", "jpg"),
    (b"GIF87a", "GIF", "gif"),
    (b"GIF89a", "GIF", "gif"),
    (b"PK\x03\x04", "ZIP (jar/apk/docx 含む)", "zip"),
    (b"\x1f\x8b\x08", "gzip", "gz"),
    (b"BZh", "bzip2", "bz2"),
    (b"\xfd7zXZ\x00", "xz", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip", "7z"),
    (b"Rar!\x1a\x07", "RAR", "rar"),
    (b"%PDF-", "PDF", "pdf"),
    (b"SQLite format 3\x00", "SQLite", "sqlite"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat / Java class", "bin"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64", "macho"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32", "macho"),
    (b"dex\n0", "Android DEX", "dex"),
    (b"OggS", "Ogg", "ogg"),
    (b"RIFF", "RIFF (WAV/AVI/WebP)", "riff"),
    (b"MEI\x0c\x0b\x0a\x0b\x0e", "PyInstaller archive cookie", "pyi"),
]
ZLIB_HEADERS = (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")


def valid(data, off, name):
    """シグネチャの後ろもそれっぽいかを確認して誤検出を減らす"""
    if name == "PE (MZ)":
        if off + 0x40 > len(data):
            return False
        pe = struct.unpack_from("<I", data, off + 0x3C)[0]
        return pe < 0x1000 and data[off + pe:off + pe + 4] == b"PE\0\0"
    if name == "ELF":
        return data[off + 4:off + 5] in (b"\x01", b"\x02") and data[off + 5:off + 6] in (b"\x01", b"\x02")
    if name == "bzip2":
        return data[off + 3:off + 4] in b"123456789" and data[off + 4:off + 10] == b"\x31\x41\x59\x26\x53\x59"
    if name == "gzip":
        try:
            d = zlib.decompressobj(31)
            return len(d.decompress(data[off:off + 65536], 64)) > 0
        except zlib.error:
            return False
    if name.startswith("Mach-O fat"):
        n = struct.unpack_from(">I", data, off + 4)[0] if off + 8 <= len(data) else 0
        return 0 < n < 20 or n >= 45  # fat: アーキ数（小さい）/ class: major version (45 以上)
    if name.startswith("RIFF"):
        return data[off + 8:off + 12] in (b"WAVE", b"AVI ", b"WEBP")
    return True


def end_of(data, off, name):
    """切り出し終端がわかる形式は計算する（不明なら None → 次の検出位置 or EOF まで）"""
    try:
        if name == "PNG":
            i = data.find(b"IEND", off)
            return i + 8 if i >= 0 else None
        if name == "JPEG":
            i = data.find(b"\xff\xd9", off)
            return i + 2 if i >= 0 else None
        if name.startswith("ZIP"):
            i = data.find(b"PK\x05\x06", off)
            if i >= 0:
                return i + 22 + struct.unpack_from("<H", data, i + 20)[0]
        if name == "gzip":
            d = zlib.decompressobj(31)
            d.decompress(data[off:])
            return len(data) - len(d.unused_data) if d.eof else None
        if name == "PE (MZ)":
            pe = off + struct.unpack_from("<I", data, off + 0x3C)[0]
            nsec, opt_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
            sec = pe + 24 + opt_size
            return off + max(sum(struct.unpack_from("<II", data, sec + i * 40 + 16)) for i in range(nsec))
        if name == "ELF":
            e = "<" if data[off + 5] == 1 else ">"
            if data[off + 4] == 2:
                shoff, = struct.unpack_from(e + "Q", data, off + 0x28)
                shentsize, shnum = struct.unpack_from(e + "HH", data, off + 0x3A)
            else:
                shoff, = struct.unpack_from(e + "I", data, off + 0x20)
                shentsize, shnum = struct.unpack_from(e + "HH", data, off + 0x2E)
            return off + shoff + shentsize * shnum if shoff else None
        if name.startswith("RIFF"):
            return off + 8 + struct.unpack_from("<I", data, off + 4)[0]
    except (struct.error, zlib.error, ValueError):
        pass
    return None


def scan_zlib(data, min_out):
    for hdr in ZLIB_HEADERS:
        off = data.find(hdr)
        while off >= 0:
            d = zlib.decompressobj()
            chunk = data[off:off + (1 << 20)]
            try:
                out = d.decompress(chunk)
                if d.eof and len(out) >= min_out:
                    end = off + len(chunk) - len(d.unused_data)
                    yield off, f"zlib stream (展開後 {len(out)} bytes)", "zlib", end, out
            except zlib.error:
                pass
            off = data.find(hdr, off + 1)


def main():
    p = argparse.ArgumentParser(description="埋め込みファイル検出・切り出し")
    p.add_argument("file")
    p.add_argument("-x", "--extract", metavar="DIR", help="検出したものを DIR に切り出す（offset 0 = ファイル自身は除く）")
    p.add_argument("--no-zlib", action="store_true", help="zlib ストリーム探索をしない（大きいファイルで遅い場合）")
    p.add_argument("--zlib-min", type=int, default=32, help="報告する zlib の最小展開サイズ (default: 32)")
    args = p.parse_args()

    data = open(args.file, "rb").read()
    hits = []
    for magic, name, ext in SIGS:
        off = data.find(magic)
        while off >= 0:
            if valid(data, off, name):
                hits.append([off, name, ext, end_of(data, off, name), None])
            off = data.find(magic, off + 1)
    if not args.no_zlib:
        hits += [list(h) for h in scan_zlib(data, args.zlib_min)]
    hits.sort(key=lambda h: h[0])

    if not hits:
        print("埋め込みファイルは見つかりませんでした")
        return
    print(f"{'offset':>10}  {'end':>10}  type")
    for i, (off, name, ext, end, _) in enumerate(hits):
        print(f"{off:#10x}  {(hex(end) if end else '?'):>10}  {name}{'  (ファイル自身)' if off == 0 else ''}")

    if args.extract:
        os.makedirs(args.extract, exist_ok=True)
        starts = sorted({h[0] for h in hits})
        for off, name, ext, end, inflated in hits:
            if off == 0:
                continue
            if end is None or name in ("ELF", "PE (MZ)"):  # 終端不明 / 実行ファイル（オーバーレイ込み）→ 次の検出位置まで
                end = next((s for s in starts if s > off), len(data))
            path = os.path.join(args.extract, f"{off:08x}.{ext}")
            with open(path, "wb") as f:
                f.write(data[off:end])
            if inflated is not None:
                with open(path + ".inflated", "wb") as f:
                    f.write(inflated)
            print(f"[+] {path} ({end - off} bytes){' + .inflated' if inflated is not None else ''}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
