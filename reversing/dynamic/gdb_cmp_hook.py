# @desc:  gdb 用 Python スクリプト: strcmp/strncmp/memcmp/strstr 等の引数を止めずにログ出力し、ptrace アンチデバッグも自動回避
# @tags:  ctf, reversing, dynamic, gdb, strcmp, memcmp, hook, anti-debug, ptrace
# @deps:  gdb（Python 対応ビルド。x86-64 / i386 / AArch64 / ARM / RISC-V / MIPS）
# @usage: gdb -q -batch -x reversing/dynamic/gdb_cmp_hook.py --args ./chall [args]
"""比較関数に渡された「正解の文字列」を覗く定番テク。プログラムは止めずに最後まで実行する。

環境変数で調整:
  HOOK_STDIN=input.txt        標準入力をファイルから与える（gdb の run < file）
  HOOK_FUNCS=strcmp,memcmp    フックする関数を変更（既定: 下の FUNCS 全部）
  HOOK_MAXLEN=128             表示する最大バイト数
  HOOK_NO_PTRACE=1            ptrace 回避を無効化
  HOOK_NORUN=1                run せずにブレークポイントだけ設定（対話で使う: gdb -x ... ./chall → run）
  HOOK_BT=1                   呼び出し元アドレスも表示（どこで比較しているか）
  HOOK_ALL=1                  libc / ld.so 内部からの呼び出しも表示（既定は本体からの呼び出しのみ）

注意: 比較がインライン展開されている / 自前ループで比較している場合は呼ばれない
      → Ghidra で比較箇所を特定し `b *0x...` と `x/s $rdi` で直接見る
"""
import os
import re

import gdb

# 関数名 → 引数の種類（s=文字列, m=メモリ（長さは n 引数）, n=長さ, w=ワイド文字列）
FUNCS = {
    "strcmp": "ss", "strncmp": "ssn", "strcasecmp": "ss", "strncasecmp": "ssn",
    "memcmp": "mmn", "bcmp": "mmn", "strstr": "ss", "wcscmp": "ww", "wcsncmp": "wwn",
    "__strcmp_chk": "ss",
}
MAXLEN = int(os.environ.get("HOOK_MAXLEN", "128"))


def arch_name():
    try:
        return gdb.selected_frame().architecture().name()
    except gdb.error:
        return gdb.selected_inferior().architecture().name()


def arg(i):
    """呼び出し直後（関数先頭）の第 i 引数"""
    a = arch_name()
    if "x86-64" in a:
        return int(gdb.parse_and_eval(["$rdi", "$rsi", "$rdx", "$rcx"][i]))
    if a.startswith("i386"):  # cdecl: [esp] = 戻りアドレス, [esp+4] = 第 1 引数
        return int(gdb.parse_and_eval(f"*(unsigned int *)($esp + {4 * (i + 1)})"))
    if "aarch64" in a:
        return int(gdb.parse_and_eval(f"$x{i}"))
    if a.startswith("arm"):
        return int(gdb.parse_and_eval(f"$r{i}"))
    if "riscv" in a or "mips" in a:
        return int(gdb.parse_and_eval(f"$a{i}"))
    raise gdb.GdbError(f"unsupported arch: {a}")


def ret_addr():
    """関数先頭での戻りアドレス（= 呼び出し元）"""
    a = arch_name()
    if "x86-64" in a:
        return int(gdb.parse_and_eval("*(unsigned long *)$rsp"))
    if a.startswith("i386"):
        return int(gdb.parse_and_eval("*(unsigned int *)$esp"))
    if "aarch64" in a:
        return int(gdb.parse_and_eval("$x30"))
    if a.startswith("arm"):
        return int(gdb.parse_and_eval("$lr")) & ~1
    return int(gdb.parse_and_eval("$ra"))


def read(addr, n):
    try:
        return bytes(gdb.selected_inferior().read_memory(addr, n))
    except gdb.MemoryError:
        return None


def read_str(addr, wide=False):
    unit = 4 if wide else 1
    out = b""
    while len(out) < MAXLEN * unit:
        chunk = read(addr + len(out), 16 * unit)
        if chunk is None:
            break
        for i in range(0, len(chunk), unit):
            if chunk[i:i + unit] == b"\0" * unit:
                return out.decode("utf-32le" if wide else "latin-1", errors="replace")
            out += chunk[i:i + unit]
    return out.decode("utf-32le" if wide else "latin-1", errors="replace") + ("…" if out else "<unreadable>")


def show(b):
    if b is None:
        return "<unreadable>"
    txt = b.decode("latin-1")
    if all(0x20 <= c < 0x7F for c in b):
        return repr(txt)
    return f"{repr(txt)}  hex={b.hex()}"


HOOKS = []


class CmpHook(gdb.Breakpoint):
    def __init__(self, name, kinds):
        super().__init__(name, internal=True)
        self.fname, self.kinds = name, kinds
        HOOKS.append(self)

    def duplicate(self, pc):
        """memcmp と bcmp のように同じアドレスに別名で張られている場合、先に作ったフックだけ残す"""
        for h in HOOKS:
            if h is self:
                return False
            if h.is_valid() and h.enabled and any(loc.address == pc for loc in getattr(h, "locations", [])):
                self.enabled = False
                return True
        return False

    def stop(self):
        if self.duplicate(int(gdb.parse_and_eval("$pc"))):
            return False
        caller = ret_addr()
        if not os.environ.get("HOOK_ALL") and gdb.solib_name(caller) is not None:
            return False  # 共有ライブラリ内部（ld.so のシンボル解決など）からの呼び出しは無視
        args = [arg(i) for i in range(len(self.kinds))]
        n = next((a for k, a in zip(self.kinds, args) if k == "n"), MAXLEN)
        parts = []
        for k, a in zip(self.kinds, args):
            if k == "s":
                parts.append(repr(read_str(a)))
            elif k == "w":
                parts.append("L" + repr(read_str(a, wide=True)))
            elif k == "m":
                parts.append(show(read(a, min(n, MAXLEN))))
            else:
                parts.append(str(a))
        where = f"  <- {caller:#x}" if os.environ.get("HOOK_BT") else ""
        gdb.write(f"\033[1;33m[hook]\033[0m {self.fname}({', '.join(parts)}){where}\n")
        return False  # 止めずに続行


class PtraceRet(gdb.FinishBreakpoint):
    """ptrace(PTRACE_TRACEME) の戻り値を 0（成功）に書き換える"""

    def stop(self):
        a = arch_name()
        reg = "$rax" if "x86-64" in a else "$eax" if a.startswith("i386") else "$x0" if "aarch64" in a \
            else "$r0" if a.startswith("arm") else "$a0"
        gdb.execute(f"set {reg} = 0")
        gdb.write("\033[1;35m[anti-debug]\033[0m ptrace(PTRACE_TRACEME) -> 0 に書き換え\n")
        return False

    def out_of_scope(self):
        pass


class PtraceHook(gdb.Breakpoint):
    def __init__(self):
        super().__init__("ptrace", internal=True)

    def stop(self):
        if arg(0) == 0:  # PTRACE_TRACEME
            PtraceRet(gdb.newest_frame(), internal=True)
        return False


gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set breakpoint pending on")
gdb.execute("set print thread-events off")
try:
    gdb.execute("set debuginfod enabled off", to_string=True)  # 起動時のシンボル DL 問い合わせを抑止（gdb 12+）
except gdb.error:
    pass

def exists(name):
    try:
        gdb.execute(f"info address {name}", to_string=True)
        return True
    except gdb.error:
        return False


def install_hooks(check_exists):
    wanted = os.environ.get("HOOK_FUNCS")
    targets = {f: FUNCS.get(f, "ss") for f in wanted.split(",")} if wanted else FUNCS
    for fname, kinds in targets.items():
        if check_exists and not exists(fname):
            continue
        CmpHook(fname, kinds)
    if not os.environ.get("HOOK_NO_PTRACE") and (not check_exists or exists("ptrace")):
        PtraceHook()


if os.environ.get("HOOK_NORUN"):
    install_hooks(check_exists=False)  # 対話用: 未ロードの関数は pending ブレークポイントになる
else:
    # エントリポイント（libc ロード済み・main 前）まで進めてからフックを張る
    gdb.execute("set suppress-cli-notifications on", to_string=True)
    stdin = os.environ.get("HOOK_STDIN")
    gdb.execute(f"starti < {stdin}" if stdin else "starti", to_string=True)
    m = re.search(r"Entry point: (0x[0-9a-f]+)", gdb.execute("info files", to_string=True))
    if m and int(gdb.parse_and_eval("$pc")) != int(m.group(1), 16):
        gdb.execute(f"tbreak *{m.group(1)}", to_string=True)
        gdb.execute("continue", to_string=True)
    gdb.execute("set suppress-cli-notifications off", to_string=True)
    install_hooks(check_exists=True)
    gdb.execute("continue")
