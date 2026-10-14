#!/usr/bin/env python3
# @desc:  USB HID キーボードの打鍵データを pcap から復元（Shift・Backspace 対応）
# @tags:  ctf, network, pcap, usb, hid, keyboard, keystroke, tshark
# @deps:  tshark（hex 行を stdin で渡す場合は不要）
# @usage: python3 network/pcap/usb_keyboard.py usb.pcapng
import argparse
import subprocess
import sys

# HID Usage ID -> (通常, Shift 時)  US 配列
KEYMAP = {i: (chr(ord("a") + i - 4), chr(ord("A") + i - 4)) for i in range(0x04, 0x1E)}
KEYMAP.update({
    0x1E: ("1", "!"), 0x1F: ("2", "@"), 0x20: ("3", "#"), 0x21: ("4", "$"), 0x22: ("5", "%"),
    0x23: ("6", "^"), 0x24: ("7", "&"), 0x25: ("8", "*"), 0x26: ("9", "("), 0x27: ("0", ")"),
    0x28: ("\n", "\n"), 0x2B: ("\t", "\t"), 0x2C: (" ", " "),
    0x2D: ("-", "_"), 0x2E: ("=", "+"), 0x2F: ("[", "{"), 0x30: ("]", "}"), 0x31: ("\\", "|"),
    0x32: ("#", "~"), 0x33: (";", ":"), 0x34: ("'", '"'), 0x35: ("`", "~"), 0x36: (",", "<"),
    0x37: (".", ">"), 0x38: ("/", "?"),
})
SPECIAL = {0x29: "<ESC>", 0x39: "<CAPS>", 0x4F: "<RIGHT>", 0x50: "<LEFT>", 0x51: "<DOWN>", 0x52: "<UP>",
           0x4C: "<DEL>"}
SHIFT_MASK = 0x22  # Left Shift (0x02) | Right Shift (0x20)


def read_reports(pcap: str):
    # 新しい Wireshark は usbhid.data、古いものは usb.capdata
    for field in ("usbhid.data", "usb.capdata"):
        out = subprocess.run(["tshark", "-r", pcap, "-T", "fields", "-e", field, "-Y", field],
                             capture_output=True, text=True).stdout
        lines = [line for line in out.splitlines() if line.strip()]
        if lines:
            return lines
    return []


def decode(reports, raw: bool):
    out = []
    caps = False
    prev = set()
    for line in reports:
        b = bytes.fromhex(line.replace(":", "").strip())
        if len(b) < 3:
            continue
        if len(b) > 8:  # 一部デバイスは先頭に Report ID 等が付く
            b = b[-8:]
        mod, keys = b[0], [k for k in b[2:] if k]
        shift = bool(mod & SHIFT_MASK)
        for k in keys:
            if k in prev:  # 押しっぱなしのキーは新規打鍵として扱わない
                continue
            if k == 0x2A:  # Backspace
                if raw:
                    out.append("<BS>")
                elif out:
                    out.pop()
            elif k == 0x39:
                caps = not caps
                if raw:
                    out.append("<CAPS>")
            elif k in KEYMAP:
                ch = KEYMAP[k][shift]
                if caps and ch.isalpha():
                    ch = ch.swapcase()
                out.append(ch)
            elif raw:
                out.append(SPECIAL.get(k, f"<0x{k:02x}>"))
        prev = set(keys)
    return "".join(out)


def main():
    p = argparse.ArgumentParser(description="USB キーボード打鍵の復元")
    p.add_argument("pcap", nargs="?", help="pcap/pcapng（省略時は stdin から hex 行を読む）")
    p.add_argument("--raw", action="store_true", help="Backspace 等を適用せず <BS> として残す")
    args = p.parse_args()

    reports = read_reports(args.pcap) if args.pcap else sys.stdin.read().split()
    if not reports:
        sys.exit("HID データが見つかりません（マウス等の可能性: 報告長 4 バイトならマウス）")
    print(decode(reports, args.raw))


if __name__ == "__main__":
    main()
