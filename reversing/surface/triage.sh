#!/usr/bin/env bash
# @desc:  リバーシング問題の最初の一手（file・ハッシュ・ELF/PE 情報・言語/パッカー判定・flag/注目文字列・エントロピーを一括表示）
# @tags:  ctf, reversing, surface, triage, overview, elf, pe, packer
# @deps:  file, python3（strings / upx / otool があれば追加情報）
# @usage: bash reversing/surface/triage.sh ./chall
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 <binary>" >&2; exit 1; }
bin=$1
[[ -f $bin ]] || { echo "error: $bin が見つかりません" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
has() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n\033[1;36m===== %s =====\033[0m\n' "$1"; }
hint() { if LC_ALL=C grep -aqE -- "$1" "$bin"; then printf '  [+] %s\n' "$2"; fi; }

section "file"
file -b "$bin"
printf 'size: %s bytes\n' "$(wc -c < "$bin" | tr -d ' ')"
if has sha256sum; then sha256sum "$bin"; else shasum -a 256 "$bin"; fi

magic=$(od -An -tx1 -N4 "$bin" | tr -d ' \n')
case $magic in
  7f454c46)
    section "ELF 情報 (elf_info.py)"
    python3 "$here/elf_info.py" "$bin" | sed '/^== sections/,$d'
    ;;
  4d5a*)
    section "PE 情報 (pe_info.py)"
    python3 "$here/pe_info.py" "$bin" | sed '/^== sections/,/^$/d'
    ;;
  cffaedfe|cefaedfe|cafebabe|feedfacf)
    section "Mach-O"
    if has otool; then otool -hv "$bin"; otool -L "$bin"; else echo "otool がないため省略（macOS で実行するか rabin2 -I を使う）"; fi
    ;;
  504b0304)
    section "ZIP 系 (jar / apk / docx 等)"
    unzip -l "$bin" 2>/dev/null | head -30 || true
    echo "  → jar: jadx / CFR / Recaf、apk: jadx-gui / apktool（static/README.md 参照）"
    ;;
esac

section "言語・パッカー・難読化の手がかり"
hint 'UPX!'                                   'UPX パック → upx -d で展開してから解析'
hint 'Go build ID|runtime\.gopanic'           'Go → GoReSym / redress で関数名復元。main.main から読む'
hint '/rustc/|rust_panic|RUST_BACKTRACE'      'Rust → <crate>::main を探す。core::/alloc:: はノイズ'
hint 'PyInstaller|_MEIPASS|pyi_rth'            'PyInstaller → pyinstxtractor → static/pyc_tool.py'
hint 'Py_Initialize|libpython3'               'Python 埋め込み（Nuitka / Cython / PyInstaller の可能性）'
hint 'Nuitka|__compiled__'                    'Nuitka（Python → C 変換。逆コンパイル困難、動的解析が有効）'
hint '_CorExeMain|mscoree\.dll'               '.NET → ILSpy / dnSpyEx / ilspycmd'
hint 'Embarcadero|Borland|TObject'            'Delphi → IDR / Ghidra + Dhrake'
hint 'AU3!|AutoIt'                            'AutoIt → AutoIt-Ripper'
hint 'app\.asar|electron'                     'Electron → npx asar extract app.asar で JS を取り出す'
hint 'lua_pcall|LuaJIT'                      'Lua 埋め込み → luadec / unluac'
hint 'GCC: \('                                'GCC でビルド'
hint 'clang version'                          'clang でビルド'
hint 'ptrace|TracerPid|IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess' \
     'アンチデバッグの可能性 → dynamic/README.md「アンチデバッグ回避」'
hint 'VirtualProtect|mprotect'                '自己書き換え / 実行時展開の可能性（mprotect / VirtualProtect）'
if has upx && LC_ALL=C grep -aq 'UPX!' "$bin"; then upx -t "$bin" 2>&1 | tail -2 || true; fi

section "flag っぽい文字列 / 注目文字列 (strings_ex.py -i)"
python3 "$here/strings_ex.py" "$bin" -i | grep -vE '\[format\]|@GLIBC|^.{0,12}\[[a-z,-]+\] .{0,3}$' | head -40 || true

section "エントロピー (entropy.py --summary)"
python3 "$here/entropy.py" "$bin" --summary

section "埋め込みファイル (embedded_scan.py)"
python3 "$here/embedded_scan.py" "$bin" --no-zlib | head -20

section "次の一手"
cat <<'EOF'
  静的: python3 reversing/surface/elf_info.py <bin> -s      # 関数シンボル一覧
        bash reversing/static/disasm.sh <bin> main           # main を逆アセンブル
        bash reversing/static/ghidra_decompile.sh <bin>      # Ghidra で全関数を C に
  動的: bash reversing/dynamic/trace.sh lib ./<bin>          # ltrace で strcmp 等を観察
        gdb -q -x reversing/dynamic/gdb_cmp_hook.py --args ./<bin>
EOF
