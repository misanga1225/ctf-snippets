#!/usr/bin/env python3
# @desc:  ファイルの MD5 / SHA1 / SHA256 を一括算出（VirusTotal 照会用 URL 付き）
# @tags:  soc, hash, md5, sha256, virustotal, forensics
# @deps:  none
# @usage: python3 soc/hash_file.py suspicious.exe --vt
import argparse
import hashlib
import sys
from pathlib import Path


def hashes(path: Path):
    hs = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            for h in hs.values():
                h.update(chunk)
    return {k: h.hexdigest() for k, h in hs.items()}


def main():
    p = argparse.ArgumentParser(description="ファイルハッシュ一括算出")
    p.add_argument("paths", nargs="+", help="ファイルまたはディレクトリ（ディレクトリは再帰）")
    p.add_argument("--vt", action="store_true", help="VirusTotal の検索 URL も表示")
    p.add_argument("--csv", action="store_true", help="CSV 形式 (path,md5,sha1,sha256)")
    args = p.parse_args()

    files = []
    for s in args.paths:
        path = Path(s)
        files += sorted(x for x in path.rglob("*") if x.is_file()) if path.is_dir() else [path]
    if args.csv:
        print("path,md5,sha1,sha256")
    for f in files:
        try:
            h = hashes(f)
        except OSError as e:
            print(f"{f}: {e}", file=sys.stderr)
            continue
        if args.csv:
            print(f"{f},{h['md5']},{h['sha1']},{h['sha256']}")
            continue
        print(f"{f}  ({f.stat().st_size} bytes)")
        for k, v in h.items():
            print(f"  {k:<7}{v}")
        if args.vt:
            print(f"  vt     https://www.virustotal.com/gui/file/{h['sha256']}")


if __name__ == "__main__":
    main()
