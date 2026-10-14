#!/usr/bin/env python3
# @desc:  テキスト/ログから IP・ドメイン・URL・ハッシュ・メールを抽出（defang 済み入力にも対応）
# @tags:  soc, ioc, extract, threat-intel, ip, domain, hash
# @deps:  none
# @usage: python3 soc/ioc_extract.py report.txt --json
import argparse
import ipaddress
import json
import re
import sys

# defang 表記を元に戻してから抽出する
REFANG = [
    (re.compile(r"hxxp(s?)", re.I), r"http\1"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", re.I), "."),
    (re.compile(r"\[@\]|\[at\]", re.I), "@"),
]

PATTERNS = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>()\[\]]+", re.I),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"),
    "domain": re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
}

# ドメインとして誤検出しやすい拡張子
FILE_EXTS = {"exe", "dll", "txt", "log", "png", "jpg", "gif", "zip", "pdf", "doc", "docx", "xls",
             "xlsx", "js", "py", "sh", "php", "html", "htm", "json", "xml", "csv", "bat", "ps1", "tmp"}


def refang(text: str) -> str:
    for pat, rep in REFANG:
        text = pat.sub(rep, text)
    return text


def extract(text: str, include_private: bool = False):
    text = refang(text)
    result = {}
    for kind, pat in PATTERNS.items():
        vals = sorted(set(m.group(0) for m in pat.finditer(text)))
        if kind == "domain":
            vals = [v for v in vals if v.rsplit(".", 1)[-1].lower() not in FILE_EXTS]
        if kind in ("ipv4", "ipv6"):
            vals = [v for v in vals if _valid_ip(v, include_private)]
        if vals:
            result[kind] = vals
    return result


def _valid_ip(v: str, include_private: bool) -> bool:
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return False
    return include_private or ip.is_global


def main():
    p = argparse.ArgumentParser(description="IOC 抽出")
    p.add_argument("files", nargs="*", help="入力ファイル（省略時は stdin）")
    p.add_argument("--json", action="store_true", help="JSON で出力")
    p.add_argument("--private", action="store_true", help="プライベート/予約 IP も含める")
    p.add_argument("-t", "--type", action="append", choices=PATTERNS, help="出力する種類を限定（複数可）")
    args = p.parse_args()

    text = "".join(open(f, encoding="utf-8", errors="replace").read() for f in args.files) \
        if args.files else sys.stdin.read()
    iocs = extract(text, args.private)
    if args.type:
        iocs = {k: v for k, v in iocs.items() if k in args.type}
    if args.json:
        print(json.dumps(iocs, indent=2, ensure_ascii=False))
        return
    for kind, vals in iocs.items():
        print(f"## {kind} ({len(vals)})")
        print("\n".join(vals))
        print()


if __name__ == "__main__":
    main()
