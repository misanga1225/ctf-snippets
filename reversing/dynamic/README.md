# 🐞 reversing/dynamic — 動的解析

**プログラムを実行して**挙動を観察する段階です。比較関数に渡る正解文字列を覗く、実行時に復号されたデータをダンプする、アンチデバッグを回避する、他アーキのバイナリを動かす、といった作業をまとめています。

← [static/（静的解析）](../static/README.md) ／ [reversing/README.md](../README.md) ／ 次: [solve/（ソルバ）](../solve/README.md)

> ⚠ 配布バイナリは**使い捨ての VM / コンテナ**で実行してください。CTF の問題でもマルウェア的な挙動（ファイル削除・通信）をするものがあります。

---

## 目次

- [どの手段を使うか](#どの手段を使うか)
- [スクリプト一覧](#スクリプト一覧)
- [スクリプトの詳しい使い方](#スクリプトの詳しい使い方)
  - [trace.sh](#tracesh) / [gdb_cmp_hook.py](#gdb_cmp_hookpy) / [ld_preload_hook.c](#ld_preload_hookc) / [frida_hook.js](#frida_hookjs) / [qemu_run.sh](#qemu_runsh)
- [gdb コマンド集](#gdb-コマンド集)
- [gdb プラグイン（pwndbg / GEF）](#gdb-プラグインpwndbg--gef)
- [strace / ltrace コマンド集](#strace--ltrace-コマンド集)
- [Apple Silicon での x86-64 デバッグ](#apple-silicon-での-x86-64-デバッグ)
- [アンチデバッグ回避](#アンチデバッグ回避)
- [パッカーの手動展開](#パッカーの手動展開)
- [Windows の動的解析](#windows-の動的解析)

---

## どの手段を使うか

| 状況 | 第一候補 | 理由 |
|---|---|---|
| とにかく比較の中身を見たい（Linux, 動的リンク） | `trace.sh cmp` | 1 行で終わる |
| ltrace が使えない（arm64 / static 以外の理由） | `gdb_cmp_hook.py` | 止めずにログ、ptrace も回避 |
| gdb を検知する / 何度も試行したい | `ld_preload_hook.c` | デバッガを使わない |
| 任意の関数の戻り値を変えたい / Android・Windows | `frida_hook.js` | 書き換えが簡単・クロスプラットフォーム |
| 特定アドレスで止めてメモリを見たい | gdb（[コマンド集](#gdb-コマンド集)） | 細かく制御できる |
| ARM / MIPS / RISC-V | `qemu_run.sh`（+ `GDB=1234`） | 実機不要 |
| 静的リンク / 自前の比較ループ | gdb でブレークポイント | ライブラリフックが効かない |

---

## スクリプト一覧

<!-- SNIPPETS:START -->

### 🐞 reversing/dynamic — 動的解析

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`frida_hook.js`](frida_hook.js) | Frida フックスクリプト（strcmp/memcmp 等の引数ログ、ptrace/IsDebuggerPresent 回避、任意アドレスでのレジスタ表示・戻り値書換） | frida-tools（pip install frida-tools）。Frida 16 / 17 両対応 | `frida -q -l reversing/dynamic/frida_hook.js -f ./chall` |
| [`gdb_cmp_hook.py`](gdb_cmp_hook.py) | gdb 用 Python スクリプト: strcmp/strncmp/memcmp/strstr 等の引数を止めずにログ出力し、ptrace アンチデバッグも自動回避 | gdb（Python 対応ビルド。x86-64 / i386 / AArch64 / ARM / RISC-V / MIPS） | `gdb -q -batch -x reversing/dynamic/gdb_cmp_hook.py --args ./chall [args]` |
| [`ld_preload_hook.c`](ld_preload_hook.c) | LD_PRELOAD 用フックライブラリ（strcmp/memcmp 等の引数ログ、ptrace アンチデバッグ回避、sleep 無効化、time/rand の固定） | gcc（対象が動的リンクされた Linux バイナリであること） | `gcc -shared -fPIC -O2 -o hook.so reversing/dynamic/ld_preload_hook.c -ldl && LD_PRELOAD=./hook.so ./chall` |
| [`qemu_run.sh`](qemu_run.sh) | ARM/AArch64/MIPS/RISC-V/PowerPC/x86 など他アーキの Linux ELF を qemu-user で実行（アーキ自動判定・sysroot 自動選択・gdb 接続待ち） | qemu-user（apt install qemu-user / qemu-user-static）、動的リンクなら libc6-<arch>-cross | `bash reversing/dynamic/qemu_run.sh ./chall_arm [args]   /   GDB=1234 bash reversing/dynamic/qemu_run.sh ./chall_arm` |
| [`trace.sh`](trace.sh) | ltrace / strace の定番オプションをモード指定で実行（ライブラリ呼び出し・比較関数・システムコール・ファイル・ネットワーク） | ltrace, strace（Linux） | `echo 'AAAA' \| bash reversing/dynamic/trace.sh cmp ./chall [args]` |

<!-- SNIPPETS:END -->

---

## スクリプトの詳しい使い方

### trace.sh

ltrace / strace をよく使うオプションで呼びます。標準入力はそのままプログラムに渡ります。

```bash
echo 'AAAA' | bash reversing/dynamic/trace.sh cmp ./chall      # 比較・文字列系の関数だけ ← まずこれ
bash reversing/dynamic/trace.sh lib ./chall arg1               # 全ライブラリ呼び出し
bash reversing/dynamic/trace.sh sys ./chall                    # 全システムコール
bash reversing/dynamic/trace.sh file ./chall                   # open/read/stat など（隠しファイル探し）
bash reversing/dynamic/trace.sh net ./chall                    # socket/connect/send
bash reversing/dynamic/trace.sh exec ./chall                   # fork / execve
bash reversing/dynamic/trace.sh sig ./chall                    # シグナル（SIGTRAP 系アンチデバッグ）
OUT=log.txt STRLEN=1024 bash reversing/dynamic/trace.sh lib ./chall   # ログ保存・長い文字列
```

```
[pid 23] crackme->strcmp("flag{AAAAAAAAAAAAA}", "open_sesame") = -145
[pid 23] crackme->memcmp("flag{", "flag{", 5)    = 0
```

> ltrace は x86 / x86-64 向け。arm64 Linux では `gdb_cmp_hook.py` か `ld_preload_hook.c` を使います。
> 静的リンクのバイナリには ltrace は効きません（strace は効きます）。

---

### gdb_cmp_hook.py

gdb の Python スクリプトです。`strcmp / strncmp / strcasecmp / memcmp / bcmp / strstr / wcscmp` にブレークポイントを張り、**止めずに引数を表示**して最後まで実行します。`ptrace(PTRACE_TRACEME)` の戻り値も自動で 0 に書き換えます。

```bash
gdb -q -batch -x reversing/dynamic/gdb_cmp_hook.py ./chall < input.txt
gdb -q -batch -x reversing/dynamic/gdb_cmp_hook.py --args ./chall arg1 arg2
HOOK_STDIN=input.txt HOOK_BT=1 gdb -q -batch -x reversing/dynamic/gdb_cmp_hook.py ./chall
```

```
[anti-debug] ptrace(PTRACE_TRACEME) -> 0 に書き換え
password: [hook] strcmp('test', 'open_sesame')  <- 0xaaaaaaaa0d08
[hook] memcmp('flag{', 'flag{', 5)
Wrong
```

| 環境変数 | 意味 |
|---|---|
| `HOOK_STDIN=file` | 標準入力をファイルから（`run < file`） |
| `HOOK_FUNCS=strcmp,memcmp` | フックする関数を指定 |
| `HOOK_BT=1` | 呼び出し元アドレスを表示（どこで比較しているか） |
| `HOOK_ALL=1` | libc / ld.so 内部からの呼び出しも表示（既定は本体からのみ） |
| `HOOK_MAXLEN=256` | 表示する最大バイト数 |
| `HOOK_NO_PTRACE=1` | ptrace 回避をしない |
| `HOOK_NORUN=1` | ブレークポイントだけ張って止まる（対話 / リモートデバッグ用） |

対話で使う・qemu のリモートデバッグに使う場合:

```bash
HOOK_NORUN=1 gdb -q -x reversing/dynamic/gdb_cmp_hook.py ./chall
(gdb) run < input.txt

# qemu-user の gdb スタブにつなぐ（他アーキ / Apple Silicon で x86-64）
HOOK_NORUN=1 gdb-multiarch -q -ex 'set sysroot /usr/x86_64-linux-gnu' \
  -x reversing/dynamic/gdb_cmp_hook.py -ex 'target remote :1234' -ex continue ./chall
```

対応アーキ: x86-64 / i386 / AArch64 / ARM / RISC-V / MIPS。
比較がインライン展開されていたり自前ループだったりすると呼ばれません → 比較箇所に `b *0x...` を張って `x/s $rdi` で見ます。

---

### ld_preload_hook.c

`LD_PRELOAD` で読み込ませるフックライブラリです。gdb を使わないので、デバッガ検知を気にせず何度でも実行できます。

```bash
gcc -shared -fPIC -O2 -o hook.so reversing/dynamic/ld_preload_hook.c -ldl
echo 'AAAA' | LD_PRELOAD=./hook.so ./chall
```

```
[anti-debug] ptrace(PTRACE_TRACEME) -> 0
[hook] time() = 1700000000
[hook] srand(1700000000) -> FAKE_SEED
[hook] strcmp("AAAA", "open_sesame")  <- 0xaaaae0760d08
```

| フック | 動作 |
|---|---|
| `strcmp` `strncmp` `strcasecmp` `memcmp` `bcmp` `strstr` | 引数を stderr に表示（バイナリは `\xNN`） |
| `ptrace(PTRACE_TRACEME)` | 常に 0（成功）を返す |
| `sleep` `usleep` `nanosleep` | 待たずに即 return（`KEEP_SLEEP=1` で無効化） |
| `time` `gettimeofday` | `FAKE_TIME=<秒>` で固定 |
| `srand` | seed を表示、`FAKE_SEED=<n>` で差し替え |

```bash
FAKE_TIME=1700000000 LD_PRELOAD=./hook.so ./chall     # srand(time(NULL)) の乱数を固定
HOOK_QUIET=1 LD_PRELOAD=./hook.so ./chall             # ログなしでアンチデバッグ回避だけ
x86_64-linux-gnu-gcc -shared -fPIC -o hook64.so reversing/dynamic/ld_preload_hook.c -ldl   # クロスビルド
gcc -m32 -shared -fPIC -o hook32.so reversing/dynamic/ld_preload_hook.c -ldl              # 32bit 版（gcc-multilib）
```

**問題の時刻を再現する例**: 「flag を `srand(time(NULL))` の乱数で暗号化した。暗号化したのは 2024-03-01 頃」
→ その日の範囲の `FAKE_TIME` を総当たりして復号結果に `flag{` が出るものを探す。

効かないケース: 静的リンク / setuid バイナリ / 関数がインライン展開 / `syscall` 命令を直接使う。

---

### frida_hook.js

Frida のスクリプトです。Linux / Windows / macOS / Android で同じものが使えます（Frida 16 / 17 両対応）。

```bash
pip install frida-tools
frida -q -l reversing/dynamic/frida_hook.js -f ./chall                     # 起動してフック
frida -q -l reversing/dynamic/frida_hook.js -f ./chall --stdio inherit < input.txt
frida -q -l reversing/dynamic/frida_hook.js -p $(pidof chall)              # 実行中のプロセスにアタッチ
frida -U -q -l reversing/dynamic/frida_hook.js -f com.example.app          # Android（USB、frida-server 起動済み）
```

ファイル先頭の `CONFIG` を書き換えて使います。

```js
const CONFIG = {
  compareFuncs: ["strcmp", "strncmp", "memcmp", ...],  // ログを取る比較関数
  antiDebug: true,          // ptrace / IsDebuggerPresent / CheckRemoteDebuggerPresent を無効化
  onlyMainModule: true,     // 本体からの呼び出しだけ表示
  // Ghidra のアドレス - イメージベース = offset。retval で戻り値を書き換え
  HOOK_OFFSETS: [{ offset: 0x11d6, name: "check", retval: 1, regs: false }],
};
```

```
[*] main module: chall @ 0xaaaad1690000 (arm64, linux)
[anti-debug] ptrace(PTRACE_TRACEME) -> 0
[hook] strcmp("flag{BBBB}", "open_sesame")  <- chall+0xd08
[offset] check called  args: 0xfffff3b2e400, ...
         arg0 as string: "flag{BBBB}"
[offset] check returned 0x0
         -> 1 に書き換え
```

**frida-trace（スクリプトなしで関数呼び出しを見る）**

```bash
frida-trace -f ./chall -i 'strcmp' -i 'memcmp'         # 関数名で
frida-trace -f ./chall -i 'libc.so*!str*'              # モジュール!パターン
frida-trace -f ./chall -a 'chall!0x11d6'               # 本体のオフセット
# __handlers__/ に自動生成される JS を編集すると引数の表示を変えられる
```

---

### qemu_run.sh

他アーキの Linux ELF を qemu-user で実行します。ELF ヘッダからアーキを判定し、Debian のクロス libc（`/usr/<triple>`）を自動で `-L` に指定します。

```bash
bash reversing/dynamic/qemu_run.sh ./chall_arm                    # 実行
echo 'AAAA' | bash reversing/dynamic/qemu_run.sh ./chall_mips     # 標準入力も渡せる
STRACE=1 bash reversing/dynamic/qemu_run.sh ./chall_arm           # システムコールログ
SYSROOT=./rootfs bash reversing/dynamic/qemu_run.sh ./chall_arm   # 配布された libc を使う
GDB=1234 bash reversing/dynamic/qemu_run.sh ./chall_arm           # gdb の接続を待つ
```

`GDB=1234` のときは別の端末で表示されたコマンドを実行します:

```bash
gdb-multiarch -q ./chall_arm -ex 'set sysroot /usr/arm-linux-gnueabihf' -ex 'target remote :1234' -ex 'b main' -ex 'c'
```

対応: x86-64 / i386 / AArch64 / ARM / ARM BE / MIPS(el)(64) / PowerPC(64)(le) / RISC-V 64 / s390x
必要なパッケージ: `qemu-user`、動的リンクなら `libc6-armhf-cross` `libc6-arm64-cross` `libc6-mips-cross` `libc6-amd64-cross` など。

---

## gdb コマンド集

```bash
gdb -q ./chall                  # 起動
gdb -q --args ./chall a b       # 引数付き
gdb -q -p <pid>                 # 実行中のプロセスにアタッチ
```

**実行制御**

| コマンド | 意味 |
|---|---|
| `r` / `r < input.txt` / `r arg1` | 実行（標準入力をファイルから） |
| `start` | main の先頭で止めて実行 |
| `starti` | 最初の命令で止める（main がない / ローダから見たい） |
| `c` | 続行 |
| `ni` / `si` | 次の命令（call に入らない / 入る） |
| `n` / `s` | 次の行（デバッグ情報がある場合） |
| `finish` | 今の関数から戻るまで実行 |
| `until *0x401200` | そのアドレスまで実行 |
| `jump *0x4013a0` | そのアドレスに飛ぶ（判定をスキップ） |
| `kill` / `q` | 終了 |

**ブレークポイント**

| コマンド | 意味 |
|---|---|
| `b main` / `b *0x401136` | 関数 / アドレス |
| `b *0x555555554000+0x11d6` | PIE（gdb は ASLR 無効で 0x555555554000 にロード） |
| `b strcmp` | ライブラリ関数（`set breakpoint pending on` で未ロードでも可） |
| `b *0x401395 if $rax == 0` | 条件付き |
| `hb *0x401136` | ハードウェアブレーク（コードを書き換えない → 0xCC 検知を回避） |
| `watch *(int*)0x404060` / `rwatch` / `awatch` | 書き込み / 読み込み / 両方で止まる |
| `catch syscall ptrace` | システムコールで止まる |
| `info b` / `d 2` / `disable 2` | 一覧 / 削除 / 無効化 |
| `commands 1` … `end` | 止まった時に自動実行するコマンド |

**表示**

| コマンド | 意味 |
|---|---|
| `info registers` / `i r rax rdi` | レジスタ |
| `x/s $rdi` | 文字列として表示（strcmp の第 1 引数） |
| `x/32bx $rsi` / `x/8gx $rsp` / `x/4wx` | バイト / 8 バイト / 4 バイト単位で hex |
| `x/10i $pc` | 現在地から 10 命令 |
| `p $rax` / `p/x $rax` / `p (char*)$rdi` | 値を表示 |
| `disas` / `disas check` | 逆アセンブル |
| `set disassembly-flavor intel` | Intel 記法（`~/.gdbinit` に書いておく） |
| `display/i $pc` | 毎回現在の命令を表示 |
| `bt` | バックトレース |
| `info proc mappings` / `vmmap`（pwndbg/GEF） | メモリマップ（PIE ベースの確認） |
| `info functions check` | 関数の検索 |
| `find /b 0x400000, 0x405000, 0x66, 0x6c, 0x61, 0x67` | メモリ検索 |

**書き換え・ダンプ**

| コマンド | 意味 |
|---|---|
| `set $rax = 0` | レジスタを書き換え（ptrace の戻り値など） |
| `set {int}0x404060 = 1` / `set {char[6]}$rdi = "hello"` | メモリを書き換え |
| `set $pc = 0x4013a0` | 実行位置を変更 |
| `dump memory out.bin 0x404000 0x405000` | メモリをファイルに保存（復号後のデータ / 展開後のコード） |
| `call (int)puts("hi")` | 関数を呼ぶ |
| `set follow-fork-mode child` | fork した子プロセスを追う |
| `handle SIGTRAP nostop noprint pass` | シグナルをプログラムに渡す（SIGTRAP 系アンチデバッグ） |
| `set disable-randomization off` | ASLR を有効に戻す（既定は無効） |

**一括実行（スクリプト化）**

```bash
gdb -q -batch -ex 'b *0x401395' -ex 'r < input.txt' -ex 'x/s $rdi' -ex 'i r rax' ./chall
gdb -q -x cmds.gdb ./chall                   # コマンドを書いたファイル
```

---

## gdb プラグイン（pwndbg / GEF）

素の gdb より圧倒的に見やすくなります（レジスタ・スタック・逆アセンブルを毎回表示）。どちらか一方を入れます。

```bash
# pwndbg
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
# GEF
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

| pwndbg | GEF | 意味 |
|---|---|---|
| `breakrva 0x11d6` | `pie breakpoint 0x11d6` | PIE のオフセットでブレーク |
| `piebase` | `pie` | PIE のベースアドレス |
| `vmmap` | `vmmap` | メモリマップ |
| `telescope $rsp 20` | `dereference $rsp 20` | ポインタを辿って表示 |
| `search "flag{"` | `search-pattern "flag{"` | メモリ全体から検索 |
| `hexdump $rdi` | `hexdump byte $rdi` | hex ダンプ |
| `checksec` | `checksec` | 保護機構 |

---

## strace / ltrace コマンド集

```bash
strace ./chall                          # 全システムコール
strace -f ./chall                       # 子プロセス・スレッドも
strace -s 256 ./chall                   # 文字列を 256 文字まで表示（既定 32）
strace -e trace=openat,read ./chall     # 絞り込み
strace -e trace=%file / %network / %process / %memory ./chall
strace -yy ./chall                      # fd をファイル名 / ソケットのアドレスで表示
strace -o log.txt -ff ./chall           # プロセスごとに log.txt.<pid> へ
strace -p <pid>                         # アタッチ
strace -c ./chall                       # システムコールの統計
strace -k ./chall                       # 各システムコールのスタックトレース

ltrace ./chall                          # ライブラリ関数呼び出し
ltrace -e strcmp+memcmp ./chall         # 関数を絞る
ltrace -s 256 -f ./chall                # 文字列長・子プロセス
ltrace -i ./chall                       # 呼び出し元アドレス付き
ltrace -S ./chall                       # システムコールも
ltrace -C ./chall                       # C++ デマングル
```

---

## Apple Silicon での x86-64 デバッグ

Docker / OrbStack の `--platform linux/amd64` コンテナは Rosetta で動くため、**ptrace が使えず gdb が失敗します**（`Couldn't get CS register: Input/output error`）。
arm64 コンテナの中で qemu-user の gdb スタブを使えばデバッグできます。

```bash
docker run --rm -it --cap-add SYS_PTRACE --security-opt seccomp=unconfined -v "$PWD":/w -w /w debian:trixie bash
apt update && apt install -y gdb-multiarch qemu-user libc6-amd64-cross python3

# 端末 1: x86-64 バイナリを gdb 待ちで起動
GDB=1234 bash reversing/dynamic/qemu_run.sh ./chall < input.txt
# 端末 2: 接続（比較フックも使える）
HOOK_NORUN=1 gdb-multiarch -q -ex 'set sysroot /usr/x86_64-linux-gnu' \
  -x reversing/dynamic/gdb_cmp_hook.py -ex 'target remote :1234' -ex continue ./chall
```

同じコンテナで `qemu-x86_64 -L /usr/x86_64-linux-gnu ./chall` と実行するだけなら gdb なしで動きます。
LD_PRELOAD フックを x86-64 で使う場合は `x86_64-linux-gnu-gcc` でビルドし `QEMU_SET_ENV=LD_PRELOAD=./hook64.so` を付けます。

---

## アンチデバッグ回避

| 手法 | 見分け方 | 回避策 |
|---|---|---|
| `ptrace(PTRACE_TRACEME)` が -1 なら終了 | import に ptrace | `gdb_cmp_hook.py` / `ld_preload_hook.c` / `frida_hook.js` が自動回避。gdb 手動なら `catch syscall ptrace` → `finish` 後 `set $rax=0`。パッチなら call を `--nop` か戻り値チェックを `--flip` |
| `/proc/self/status` の `TracerPid` を読む | strings に `TracerPid` | 読んだ値のチェック分岐を `patch_bytes.py --flip`、または gdb で比較時にレジスタを書き換え |
| 親プロセス名が gdb か確認 | `/proc/%d/cmdline`, `getppid` | 同上 / gdb でなく `ld_preload_hook` を使う |
| 実行時間の計測（`rdtsc`, `clock_gettime`, `time`） | 2 回計測して差を比較 | ブレークポイントを置かずに `gdb_cmp_hook.py`（止めない）、`FAKE_TIME`、差の比較をパッチ |
| `int3` / SIGTRAP を自分で処理 | `signal(SIGTRAP, ...)`, `int3` 命令 | gdb で `handle SIGTRAP nostop noprint pass` |
| コードのチェックサム / 0xCC 検知 | 自分の `.text` を読んで合計 | ソフトウェアブレークポイントを使わず `hb`（ハードウェア）か Frida |
| `LD_PRELOAD` 検知 | strings に `LD_PRELOAD` | gdb / Frida を使う、getenv をパッチ |
| `IsDebuggerPresent` / PEB.BeingDebugged（Windows） | import | x64dbg + ScyllaHide、`frida_hook.js`、戻り値の分岐をパッチ |
| `NtQueryInformationProcess(ProcessDebugPort)` | import / 動的解決 | ScyllaHide |
| TLS コールバック（Windows） | `pe_info.py` で表示 | x64dbg の設定で「TLS コールバックで停止」→ 中身を確認してパッチ |

---

## パッカーの手動展開

`upx -d` で展開できない独自パッカー / 改造 UPX の場合、**実行させて展開後のメモリをダンプ**します。

```bash
gdb -q ./packed
(gdb) catch syscall mprotect munmap     # 展開後に権限変更 / アンマップすることが多い
(gdb) r
(gdb) info proc mappings                # 展開先の領域を確認
(gdb) dump memory unpacked.bin 0x400000 0x420000
```

取り出したメモリは ELF として不完全なので、Ghidra に **Raw Binary** として読み込み、ベースアドレスを `0x400000` に指定して解析します。
UPX の場合は、展開後に元のエントリポイント（OEP）へ `jmp` する直前で止めるのが定番です。

---

## Windows の動的解析

| ツール | 用途 |
|---|---|
| x64dbg | デバッガ（`F2` ブレーク / `F7` ステップイン / `F8` ステップオーバー / `F9` 実行 / `Ctrl+G` ジャンプ / `Ctrl+B` バイト検索） |
| ScyllaHide | x64dbg のアンチアンチデバッグプラグイン |
| Scylla | 実行中プロセスのダンプ・IAT 再構築（パッカー展開） |
| Process Monitor | ファイル・レジストリ・プロセスの操作ログ |
| API Monitor | Win32 API 呼び出しのログ |
| dnSpyEx | .NET のデバッグ（変数書き換え・ステップ実行） |
| Wine | Linux で exe を動かす（`wine chall.exe`。デバッグは `winedbg`） |
