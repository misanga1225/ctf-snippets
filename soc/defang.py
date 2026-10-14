#!/usr/bin/env python3
# @desc:  IOC の defang / refang 変換（hxxp, [.], [@] など）
# @tags:  soc, ioc, defang, refang, threat-intel
# @deps:  none
# @usage: echo 'http://evil.com/a' | python3 soc/defang.py
import argparse
import re
import sys


def defang(text: str) -> str:
    text = re.sub(r"\bhttp(s?)://", r"hxxp\1[://]", text, flags=re.I)
    text = re.sub(r"\bftp://", "fxp[://]", text, flags=re.I)
    text = text.replace("@", "[@]")
    # IP やドメイン中の '.' のみ置換（文末のピリオドは残す）
    return re.sub(r"(?<=[A-Za-z0-9])\.(?=[A-Za-z0-9])", "[.]", text)


def refang(text: str) -> str:
    text = re.sub(r"hxxp(s?)", r"http\1", text, flags=re.I)
    text = re.sub(r"fxp", "ftp", text, flags=re.I)
    text = re.sub(r"\[://\]|\[:\]//", "://", text)
    text = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", text, flags=re.I)
    return re.sub(r"\[@\]|\[at\]|\(at\)", "@", text, flags=re.I)


def main():
    p = argparse.ArgumentParser(description="IOC の defang/refang")
    p.add_argument("-r", "--refang", action="store_true", help="refang（元に戻す）")
    p.add_argument("file", nargs="?", help="入力ファイル（省略時は stdin）")
    args = p.parse_args()

    text = open(args.file, encoding="utf-8").read() if args.file else sys.stdin.read()
    sys.stdout.write(refang(text) if args.refang else defang(text))


if __name__ == "__main__":
    main()
