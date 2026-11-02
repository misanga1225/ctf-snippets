#!/usr/bin/env python3
# @desc:  strings の強化版（ASCII + UTF-16LE/BE/UTF-32、オフセット表示、flag/URL/成功失敗メッセージ/base64 テーブル等の分類）
# @tags:  ctf, reversing, surface, strings, utf16, wide, flag, base64
# @deps:  none
# @usage: python3 reversing/surface/strings_ex.py ./chall --interesting
"""Windows バイナリの UTF-16 文字列（GNU strings では -el が必要）や独自 base64 テーブルも拾う。"""
import argparse
import re
import sys

CATEGORIES = [
    ("flag", re.compile(r"[A-Za-z0-9_]{2,}\{[^}]{2,}\}|flag|ctf", re.I)),
    ("message", re.compile(r"correct|wrong|incorrect|success|fail|congrat|nope|try again|invalid|good job|"
                           r"well done|password|passwd|enter|input|key:|serial|license|access (granted|denied)", re.I)),
    ("url", re.compile(r"https?://|ftp://|wss?://", re.I)),
    ("path", re.compile(r"^/(etc|proc|tmp|dev|home|usr|bin|var)/|[A-Za-z]:\\|\\\\", re.I)),
    ("anti-debug", re.compile(r"ptrace|TracerPid|/proc/self/(status|maps)|IsDebuggerPresent|"
                              r"CheckRemoteDebugger|gdb|frida|ida|x64dbg|ollydbg|LD_PRELOAD", re.I)),
    ("crypto", re.compile(r"\b(aes|rc4|des|rsa|sha-?\d+|md5|chacha|salsa|xtea|tea|blowfish|hmac|crc32)\b", re.I)),
    ("format", re.compile(r"%[-+ #0]*\d*(\.\d+)?(l{0,2}|h{0,2}|z)[sdxXuicp]")),
]


def is_b64_table(s: str) -> bool:
    """64/65 文字の重複なし英数字列 → base64 の（独自）変換テーブルの可能性"""
    return len(s) in (64, 65) and len(set(s)) == len(s) and sum(c.isalnum() for c in s) >= 60


def scan(data: bytes, min_len: int, encodings):
    pats = {
        "ascii": (re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len), "ascii", 1),
        "utf16le": (re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % min_len), "utf-16le", 2),
        "utf16be": (re.compile(rb"(?:\x00[\x20-\x7e\t]){%d,}" % min_len), "utf-16be", 2),
        "utf32le": (re.compile(rb"(?:[\x20-\x7e\t]\x00\x00\x00){%d,}" % min_len), "utf-32le", 4),
    }
    for enc in encodings:
        regex, codec, _ = pats[enc]
        for m in regex.finditer(data):
            yield m.start(), enc, m.group().decode(codec, errors="replace")


def main():
    p = argparse.ArgumentParser(description="strings 強化版")
    p.add_argument("file", nargs="?", help="対象ファイル（省略時は stdin）")
    p.add_argument("-n", "--min-len", type=int, default=4, help="最小文字数 (default: 4)")
    p.add_argument("-e", "--encoding", default="ascii,utf16le",
                   help="ascii,utf16le,utf16be,utf32le（Linux の wchar_t）のカンマ区切り / all (default: ascii,utf16le)")
    p.add_argument("-g", "--grep", help="正規表現で絞り込み（大文字小文字無視）")
    p.add_argument("-i", "--interesting", action="store_true", help="分類に当てはまる文字列だけ表示（カテゴリ付き）")
    p.add_argument("--no-offset", action="store_true", help="オフセットを表示しない")
    args = p.parse_args()

    data = open(args.file, "rb").read() if args.file else sys.stdin.buffer.read()
    encs = ["ascii", "utf16le", "utf16be", "utf32le"] if args.encoding == "all" else args.encoding.split(",")
    grep = re.compile(args.grep, re.I) if args.grep else None
    rows = sorted(scan(data, args.min_len, encs))
    for off, enc, s in rows:
        if grep and not grep.search(s):
            continue
        tags = [name for name, rx in CATEGORIES if rx.search(s)]
        if is_b64_table(s):
            tags.append("b64-table" if s.startswith("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef") else "b64-table(custom?)")
        if args.interesting and not tags:
            continue
        prefix = "" if args.no_offset else f"{off:#010x} "
        enc_tag = "" if enc == "ascii" else f"[{enc}] "
        tag = f"[{','.join(tags)}] " if args.interesting else ""
        print(f"{prefix}{enc_tag}{tag}{s}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
