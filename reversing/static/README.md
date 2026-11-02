# 🧩 reversing/static — 静的解析・パッチ

**プログラムを実行せずに**中身を読む段階です。逆アセンブル・逆コンパイルで main → 判定関数を見つけ、入力がどう変換・比較されるかを読み解きます。
比較対象のデータ抽出、バイナリパッチ、言語別（.NET / Java / Python / Go …）のデコンパイラもここにまとめています。

← [surface/（表層解析）](../surface/README.md) ／ [reversing/README.md](../README.md) ／ 次: [dynamic/（動的解析）](../dynamic/README.md)・[solve/（ソルバ）](../solve/README.md)

---

## 目次

- [静的解析の進め方](#静的解析の進め方)
- [スクリプト一覧](#スクリプト一覧)
- [スクリプトの詳しい使い方](#スクリプトの詳しい使い方)
  - [disasm.sh](#disasmsh) / [r2_analyze.sh](#r2_analyzesh) / [ghidra_decompile.sh + DecompileAll.java](#ghidra_decompilesh--decompilealljava) / [extract_bytes.py](#extract_bytespy) / [patch_bytes.py](#patch_bytespy) / [pyc_tool.py](#pyc_toolpy)
- [Ghidra の使い方（GUI）](#ghidra-の使い方gui)
- [IDA Free の使い方](#ida-free-の使い方)
- [radare2 コマンド集](#radare2-コマンド集)
- [objdump コマンド集](#objdump-コマンド集)
- [x86-64 / ARM64 アセンブリ早見表](#x86-64--arm64-アセンブリ早見表)
- [暗号・エンコードの見分け方（定数）](#暗号エンコードの見分け方定数)
- [言語・プラットフォーム別](#言語プラットフォーム別)

---

## 静的解析の進め方

1. **入口を探す**: `main`（stripped なら `disasm.sh --entry`）、または成功/失敗メッセージの参照元（`r2_analyze.sh xref Correct`）
2. **判定関数を特定**: `main` から呼ばれていて、入力バッファを引数に取り、戻り値で分岐している関数
3. **入力の流れを追う**: 長さチェック → 変換（XOR / 加算 / テーブル置換 / 暗号）→ 比較。変数名を付け直しながら読む
4. **比較対象を取り出す**: 配列のアドレスを `extract_bytes.py` で Python リスト化
5. **逆算する**: 単純なら Python で逆変換、複雑なら [solve/](../solve/README.md) の Z3 / angr

---

## スクリプト一覧

<!-- SNIPPETS:START -->

### 🧩 reversing/static — 静的解析・パッチ

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`DecompileAll.java`](DecompileAll.java) | Ghidra ヘッドレス用ポストスクリプト（全関数 or 名前一致の関数を逆コンパイルして 1 つの C ファイルに出力） | Ghidra 10 以上（ghidra_decompile.sh から呼ばれる） | `analyzeHeadless /tmp/proj p -import ./chall -scriptPath reversing/static -postScript DecompileAll.java out.c [filter] -deleteProject` |
| [`disasm.sh`](disasm.sh) | objdump ラッパー（Intel 記法で関数/アドレス範囲を逆アセンブル、関数一覧、stripped バイナリの main 特定） | objdump（GNU binutils または llvm-objdump）, nm | `bash reversing/static/disasm.sh ./chall [main\|0x401136\|--list\|--entry\|--all] [len=0x100]` |
| [`extract_bytes.py`](extract_bytes.py) | ELF/PE の仮想アドレス・シンボル名・ファイルオフセットからデータを抜き出し C 配列/Python リスト/u32 配列等に整形（暗号化テーブルの取り出し用） | none | `python3 reversing/static/extract_bytes.py ./chall --sym enc_flag -f py` |
| [`ghidra_decompile.sh`](ghidra_decompile.sh) | Ghidra をヘッドレス実行して全関数（または指定関数）を C 言語に逆コンパイルしファイル出力（GUI 不要） | Ghidra（analyzeHeadless）, Java 17+ | `bash reversing/static/ghidra_decompile.sh ./chall [out.c] [関数名フィルタ]` |
| [`patch_bytes.py`](patch_bytes.py) | バイナリパッチ（VA/オフセット指定でバイト書換・NOP 埋め・条件分岐反転・常に jmp・即 return）とバイト列検索 | none | `python3 reversing/static/patch_bytes.py ./chall --addr 0x4012a5 --flip -o ./chall.patched` |
| [`pyc_tool.py`](pyc_tool.py) | .pyc の Python バージョン判定・ヘッダ修復（pyinstxtractor 出力向け）・逆アセンブル/定数一覧（同バージョンの Python で実行時） | none（逆コンパイルは pycdc / decompyle3 / uncompyle6 を別途） | `python3 reversing/static/pyc_tool.py info chall.pyc` |
| [`r2_analyze.sh`](r2_analyze.sh) | radare2 を非対話で実行して定番の解析結果を出す（情報・関数一覧・main 逆アセ/疑似 C・文字列・文字列の参照元・呼び出し関係） | radare2（R2=rizin で rizin も可。dec は r2ghidra / r2dec があれば使う） | `bash reversing/static/r2_analyze.sh ./chall [info\|funcs\|main\|func <名前\|0xaddr>\|dec <名前>\|strings\|xref <文字列>\|calls <名前>]` |

<!-- SNIPPETS:END -->

---

## スクリプトの詳しい使い方

### disasm.sh

objdump を Intel 記法・C++ デマングル・機械語バイト非表示で呼ぶラッパーです。GNU objdump / llvm-objdump（macOS 標準）の両方に対応。

```bash
bash reversing/static/disasm.sh ./chall                 # main を逆アセンブル
bash reversing/static/disasm.sh ./chall check           # 関数名を指定
bash reversing/static/disasm.sh ./chall 0x401136 0x80   # アドレスから 0x80 バイト
bash reversing/static/disasm.sh ./chall --list          # 関数シンボル一覧（アドレス順）
bash reversing/static/disasm.sh ./chall --entry         # stripped バイナリの main を推定
bash reversing/static/disasm.sh ./chall --all | less    # .text 全体
RAW=1 bash reversing/static/disasm.sh ./chall main      # 機械語バイトも表示（パッチ用）
OBJDUMP=x86_64-linux-gnu-objdump bash reversing/static/disasm.sh ./chall   # objdump を指定
```

`--entry` の仕組み: glibc の `_start` は `main` のアドレスを第 1 引数（rdi）に入れて `__libc_start_main` を呼ぶので、その値を拾います。

```
[+] main は 0x1294 の可能性（__libc_start_main の第 1 引数）→ disasm.sh ./chall 0x1294
```

> arm64 Linux の GNU objdump は x86 を逆アセンブルできません。`binutils-x86-64-linux-gnu`（`x86_64-linux-gnu-objdump`）か llvm-objdump を `OBJDUMP=` で指定してください。

---

### r2_analyze.sh

radare2 を非対話で実行し、定番の解析結果を出します（`R2=rizin` で rizin も可）。

```bash
bash reversing/static/r2_analyze.sh ./chall info              # 概要・エントリ・インポート
bash reversing/static/r2_analyze.sh ./chall                   # 関数一覧（サイズ順）
bash reversing/static/r2_analyze.sh ./chall main              # main の逆アセンブル
bash reversing/static/r2_analyze.sh ./chall func sym.check    # 関数を指定（アドレスも可）
bash reversing/static/r2_analyze.sh ./chall dec sym.check     # 疑似 C（r2ghidra > r2dec > pdc）
bash reversing/static/r2_analyze.sh ./chall strings           # 文字列（仮想アドレス付き）
bash reversing/static/r2_analyze.sh ./chall xref Correct      # 文字列の参照元 = 判定箇所
bash reversing/static/r2_analyze.sh ./chall calls main        # main が呼ぶ関数・参照する文字列
```

出力例（`xref`）:

```
## Correct! @ 0x004020e0
main 0x401397 [STRN:r--] lea rax, str.Correct_      ← main の 0x401397 で "Correct!" を参照
```

r2ghidra（Ghidra の逆コンパイラを r2 で使うプラグイン）を入れると `dec` の品質が上がります: `r2pm -ci r2ghidra`

---

### ghidra_decompile.sh + DecompileAll.java

Ghidra を GUI なしで実行し、全関数（または名前に一致する関数）を 1 つの C ファイルに逆コンパイルします。
grep で探したり、エディタで読んだり、LLM に貼ったりするのに便利です。

```bash
bash reversing/static/ghidra_decompile.sh ./chall                  # → ./chall.c
bash reversing/static/ghidra_decompile.sh ./chall out.c            # 出力先を指定
bash reversing/static/ghidra_decompile.sh ./chall out.c check      # 名前に "check" を含む関数だけ
GHIDRA_HOME=~/ghidra_11.4_PUBLIC bash reversing/static/ghidra_decompile.sh ./chall
```

```c
// ===== check @ 004011d6 =====
undefined8 check(char *param_1)
{
  sVar2 = strlen(param_1);
  if (sVar2 == 0x13) {
    iVar1 = memcmp(param_1,"flag{",5);
    ...
        if (((uint)(byte)param_1[local_c] ^ local_c * 7 + 0x13U & 0xff) != (uint)(byte)enc_flag[local_c]) {
```

- `analyzeHeadless` は `$GHIDRA_HOME/support/` → PATH → Homebrew → `/opt/ghidra*` → `~/ghidra*` の順に探します
- 小さいバイナリで数秒〜十数秒、大きい（Go / static）と数分かかります
- 直接使う場合: `analyzeHeadless /tmp/proj p -import ./chall -scriptPath reversing/static -postScript DecompileAll.java out.c -deleteProject`

---

### extract_bytes.py

ELF / PE の**仮想アドレス・シンボル名・ファイルオフセット**からデータを抜き出し、ソルバに貼れる形に整形します。

```bash
python3 reversing/static/extract_bytes.py ./chall --sym enc_flag -f py          # シンボル名（サイズ自動）
python3 reversing/static/extract_bytes.py ./chall --addr 0x404070 -n 19         # objdump のアドレス
python3 reversing/static/extract_bytes.py ./chall --addr 0x104070 --base 0x100000 -n 19   # Ghidra のアドレス
python3 reversing/static/extract_bytes.py ./chall --addr 0x4020 -n 64 -f u32    # 32bit 整数配列として
python3 reversing/static/extract_bytes.py ./chall --offset 0x3070 -n 19 -o enc.bin   # ファイルに保存
python3 reversing/static/extract_bytes.py ./chall.exe --addr 0x140008000 -n 32  # PE（ImageBase 込みの VA）
```

| `-f` | 出力 |
|---|---|
| `xxd`（既定） | アドレス付き hex ダンプ |
| `py` | `[0x75, 0x76, ...]`（Python / Z3 にそのまま貼れる） |
| `bytes` | `b'uv@O...'` |
| `c` | `unsigned char enc_flag[19] = { ... };` |
| `hex` | `7576404f...` |
| `u16` / `u32` / `u64` / `i32` | 整数配列（`--be` でビッグエンディアン） |
| `raw` | 生バイナリを stdout へ |

`.bss`（初期値ゼロで実行時に書き込まれる領域）を指定するとエラーになります。その場合は gdb で実行中にダンプします（`dump memory out.bin 0x... 0x...`）。

---

### patch_bytes.py

バイナリにパッチを当てます。既定では元ファイルを残して `<file>.patched` を作ります。

```bash
# 条件分岐の反転（je ⇔ jne など）。判定結果を逆にする
python3 reversing/static/patch_bytes.py ./chall --addr 0x401395 --flip
# 条件分岐を無条件 jmp に（常に分岐させる）
python3 reversing/static/patch_bytes.py ./chall --addr 0x401395 --jmp
# 関数を「return 1」に（check() を常に成功させる）
python3 reversing/static/patch_bytes.py ./chall --addr 0x4011d6 --ret 1
# NOP 埋め（ptrace チェックの call 命令 5 バイトを潰す等）
python3 reversing/static/patch_bytes.py ./chall --addr 0x4012bd --nop 5
# 任意のバイト列
python3 reversing/static/patch_bytes.py ./chall --offset 0x1395 --bytes '75'
# バイト列検索（?? はワイルドカード）。パッチ箇所を探す
python3 reversing/static/patch_bytes.py ./chall --find '85 c0 74 ??'
# Ghidra のアドレスで指定 / 上書き保存
python3 reversing/static/patch_bytes.py ./chall --addr 0x101395 --base 0x100000 --flip -o ./chall
```

```
offset 0x1395: 74  ->  75
[+] ./chall.patched
```

| オプション | x86 / x64 | AArch64 |
|---|---|---|
| `--flip` | `7x` の下位 1bit 反転 / `0f 8x` の下位 1bit 反転 | — |
| `--jmp` | `7x` → `eb` / `0f 8x rel32` → `e9 rel32+1; 90` | — |
| `--ret N` | `mov eax, N; ret`（N=0 は `xor eax,eax; ret`） | `mov w0, #N; ret` |
| `--nop N` | `90` × N | `1f 20 03 d5` × N/4 |

> flag がプログラム内で**復号されて表示される**タイプならパッチで判定を通せば flag が出ます。入力そのものが flag のタイプ（入力 == 正解）では、パッチしても「Correct」が出るだけで flag はわかりません。
> macOS の Mach-O をパッチした場合は `codesign -f -s - <file>` で再署名が必要です。

**よく使う x86 の条件分岐**

| short | near | 意味 | 反転先 |
|---|---|---|---|
| `74` | `0f 84` | je / jz（等しい） | `75` / `0f 85` |
| `75` | `0f 85` | jne / jnz | `74` / `0f 84` |
| `7c` / `7d` | `0f 8c` / `0f 8d` | jl / jge（符号付き） | 互いに |
| `7e` / `7f` | `0f 8e` / `0f 8f` | jle / jg（符号付き） | 互いに |
| `72` / `73` | `0f 82` / `0f 83` | jb / jae（符号なし） | 互いに |
| `eb` | `e9` | jmp | — |

---

### pyc_tool.py

PyInstaller 製 exe や配布された `.pyc` を解析します。

```bash
python3 reversing/static/pyc_tool.py info chall.pyc           # バージョン判定 + 逆コンパイラの提案
python3 reversing/static/pyc_tool.py consts chall.pyc         # 定数・名前の一覧（flag や鍵が入っていることが多い）
python3 reversing/static/pyc_tool.py dis chall.pyc            # 逆アセンブル
python3 reversing/static/pyc_tool.py fix mod.pyc --ver 3.10   # ヘッダが欠けた pyc を修復
```

- `dis` / `consts` は **pyc と同じバージョンの Python で実行**する必要があります（marshal 形式がバージョンごとに違うため）。
  バージョンが違うと案内が出ます: `uv run --python 3.10 reversing/static/pyc_tool.py dis chall.pyc`
- `fix`: pyinstxtractor の出力のうち PYZ 内のモジュールはヘッダが欠けていることがあります。メインスクリプトの pyc と同じバージョンを `--ver` に指定します

**PyInstaller exe の展開手順**

```bash
# 1. 展開（chall.exe_extracted/ ができる）
git clone https://github.com/extremecoders-re/pyinstxtractor
python3 pyinstxtractor/pyinstxtractor.py ./chall.exe
#    → 出力の "Python version: 3.10" を控える / メインは chall.pyc（エントリポイント名）
# 2. バージョン確認と定数の確認
python3 reversing/static/pyc_tool.py info chall.exe_extracted/chall.pyc
uv run --python 3.10 reversing/static/pyc_tool.py consts chall.exe_extracted/chall.pyc
# 3. 逆コンパイル
pycdc chall.exe_extracted/chall.pyc          # Decompyle++（新しいバージョンにも部分対応）
decompyle3 chall.exe_extracted/chall.pyc     # 3.7〜3.8
uncompyle6 chall.exe_extracted/chall.pyc     # 〜3.8
#    3.9 以降で失敗する部分は dis の結果を読む / PyLingual (https://pylingual.io) を試す
```

---

## Ghidra の使い方（GUI）

起動: `ghidraRun` → File → New Project → `I` キー（Import File）でバイナリを取り込み → ダブルクリックで CodeBrowser → 「Analyze?」で Yes（既定のまま）。

| 操作 | キー / メニュー |
|---|---|
| アドレス / 関数名へジャンプ | `G` |
| 名前の変更（関数・変数・ラベル） | `L` |
| 変数の型を変更 | `Ctrl+L` |
| コメント | `;` |
| 参照元一覧（xref） | 名前を右クリック → References → Show References to（`Ctrl+Shift+F`） |
| 文字列の一覧 | Window → Defined Strings（または Search → For Strings） |
| 関数の一覧 | Window → Functions |
| 逆コンパイル画面 | Window → Decompile（`Ctrl+E`） |
| 前の場所に戻る | `Alt+←` |
| バイト列の検索 | Search → Memory（`S`） |
| パッチ | Listing で右クリック → Patch Instruction（`Ctrl+Shift+G`）→ File → Export Program（Original File 形式） |
| スクリプト | Window → Script Manager（Java / Python） |

**読み方のコツ**

- `main` は Symbol Tree → Functions から。stripped なら `entry` → `__libc_start_main` の第 1 引数
- `param_1` などの変数名は `L` で `input` / `len` / `key` に付け直すと一気に読みやすくなる
- `local_38 = 0x6c662f...` のような**連続した即値代入**はスタック上の文字列/配列。右クリック → Convert → Char Sequence
- 配列が `undefined` のまま → 右クリック → Data → 型を選ぶ（`byte[32]` など）
- 自作関数を優先して読む（libc の関数は名前が付いている。static リンクで名前がない場合は Function ID / BSim）
- Go のバイナリは Ghidra 10.3 以降で関数名が復元される。古い場合は GoReSym の出力を読み込む

---

## IDA Free の使い方

| 操作 | キー |
|---|---|
| 逆コンパイル（x86/x64 のクラウド逆コンパイラ） | `F5` |
| グラフ ⇔ テキスト表示 | `Space` |
| 逆アセンブル ⇔ 疑似コード | `Tab` |
| ジャンプ | `G` |
| 名前変更 | `N` |
| 型変更 | `Y` |
| 参照元（xref） | `X` |
| 文字列一覧 | `Shift+F12` |
| コメント | `:` / `;` |
| 16 進表示 / 文字表示に変換 | `H` / `R` |
| 戻る | `Esc` |

---

## radare2 コマンド集

```bash
r2 -A ./chall          # 解析してから対話モード（-A = aaa）
r2 -d ./chall          # デバッガとして起動
r2 -w ./chall          # 書き込みモード（パッチ）
```

| コマンド | 意味 |
|---|---|
| `aaa` | 全体を解析（関数・参照） |
| `afl` | 関数一覧 / `afl~check` で grep |
| `s main` / `s 0x401136` | シーク（移動） |
| `pdf` | 現在の関数を逆アセンブル |
| `pdf @ sym.check` | 指定関数を逆アセンブル |
| `pdc` / `pdg` / `pdd` | 疑似 C（内蔵 / r2ghidra / r2dec） |
| `iz` / `izz` | 文字列（データセクション / 全体） |
| `axt @ 0x4020e0` | そのアドレスへの参照元 |
| `axf @ 0x401397` | そのアドレスからの参照先 |
| `afx` | 現在の関数が参照する関数・データ |
| `VV` | ビジュアルグラフモード（`q` で抜ける） |
| `/ Correct` / `/x 85c074` | 文字列 / バイト列の検索 |
| `px 64 @ obj.enc_flag` | hex ダンプ |
| `pcp 19 @ obj.enc_flag` | Python 形式で出力 |
| `wx 75 @ 0x401395` | バイト書き込み（`-w` で開いた時） |
| `wa "jmp 0x4013a8" @ 0x401395` | アセンブルして書き込み |
| `?` / `pd?` | ヘルプ（コマンド末尾に `?`） |

---

## objdump コマンド集

```bash
objdump -d -M intel ./chall | less                     # 全体を Intel 記法で
objdump -d -M intel --no-show-raw-insn -C ./chall      # 機械語なし・デマングル
objdump -d -M intel --disassemble=main ./chall         # 関数指定（binutils 2.32+）
objdump -d -M intel --start-address=0x401136 --stop-address=0x401200 ./chall
objdump -d -j .text ./chall                            # セクション指定
objdump -s -j .rodata ./chall                          # データを hex + ASCII
objdump -d -M intel ./chall | grep -B5 'call.*strcmp'  # strcmp を呼ぶ箇所の直前
objdump -D -b binary -m i386:x86-64 -M intel shellcode.bin   # 生バイナリを逆アセンブル
```

---

## x86-64 / ARM64 アセンブリ早見表

**呼び出し規約（引数・戻り値）**

| | 第1 | 第2 | 第3 | 第4 | 第5 | 第6 | 戻り値 |
|---|---|---|---|---|---|---|---|
| x86-64 System V（Linux/macOS） | rdi | rsi | rdx | rcx | r8 | r9 | rax |
| x86-64 Windows | rcx | rdx | r8 | r9 | スタック | | rax |
| x86 cdecl（32bit） | [esp+4] | [esp+8] | [esp+12] | … | | | eax |
| AArch64 | x0 | x1 | x2 | x3 | x4 | x5 | x0 |
| ARM32 | r0 | r1 | r2 | r3 | スタック | | r0 |
| MIPS / RISC-V | a0 | a1 | a2 | a3 | … | | v0 / a0 |

**よく出る命令（x86-64, Intel 記法 `命令 宛先, 元`）**

| 命令 | 意味 |
|---|---|
| `mov rax, [rbp-0x18]` | メモリから読む |
| `lea rax, [rip+0x2e9f]` | アドレスを計算（読まない）。文字列・配列のアドレス取得 |
| `movzx eax, byte ptr [rax]` | 1 バイト読んでゼロ拡張（`s[i]` の読み出し） |
| `xor eax, eax` | eax = 0 |
| `test eax, eax` → `je` | eax == 0 なら分岐 |
| `cmp eax, 0x13` → `jne` | eax != 0x13 なら分岐 |
| `imul` / `idiv` / `shl` / `sar` / `shr` / `rol` / `ror` | 乗算 / 除算 / シフト / ローテート |
| `call` / `ret` / `leave` | 関数呼び出し / 戻る / スタックフレーム解放 |
| `movaps` / `pxor` / `pshufb` / `aesenc` | SIMD / AES-NI（暗号処理の目印） |

**AArch64**: `ldr/str`（読み書き）, `ldrb`（1 バイト）, `adrp x0, page; add x0, x0, #off`（アドレス取得）, `cmp` → `b.eq/b.ne`, `cbz/cbnz`（0 比較で分岐）, `bl`（call）, `ret`, `eor`（XOR）, `lsl/lsr/ror`。

---

## 暗号・エンコードの見分け方（定数）

逆コンパイル結果に出てくる**特徴的な定数**から、使われているアルゴリズムを推定できます。
Ghidra の FindCrypt プラグイン、`capa`（Mandiant）でも自動検出できます。

| 定数 / 特徴 | アルゴリズム |
|---|---|
| `63 7c 77 7b f2 6b 6f c5`（256 バイトの表） | AES S-box |
| `0x9e3779b9` / `0x61c88647` | TEA / XTEA / XXTEA（delta）、黄金比ハッシュ |
| `0x67452301 0xefcdab89 0x98badcfe 0x10325476` | MD5 / SHA-1 の初期値 |
| `0x6a09e667 0xbb67ae85 …` / `0x428a2f98 …` | SHA-256 |
| `0xedb88320` / `0x04c11db7` | CRC32 |
| `"expand 32-byte k"` | ChaCha20 / Salsa20 |
| 0〜255 で初期化した配列を `j = j + S[i] + key[i % len]` で混ぜる | RC4 |
| `ABC…xyz0123456789+/` の 64 文字 | base64（並びが違えば独自テーブル） |
| `1103515245, 12345` / `0x41c64e6d, 0x3039` | glibc 系 LCG（rand） |
| `0x5deece66d` | Java の Random / drand48 |
| `x ^= x << 13; x ^= x >> 17; x ^= x << 5` | xorshift32 |
| `0x811c9dc5, 0x01000193` | FNV-1a ハッシュ |
| `% 26` と `+ 'a'` | シーザー / ヴィジュネル |

> 単純な XOR / 加算 / 置換なら Python で逆変換。AES / RC4 などは鍵と IV を見つけて `pycryptodome` で復号するのが早道です。

---

## 言語・プラットフォーム別

### .NET (C#)

```bash
dotnet tool install -g ilspycmd
ilspycmd chall.exe                     # C# を標準出力に
ilspycmd -p -o out/ chall.exe          # プロジェクトとして書き出し
```

GUI: ILSpy（閲覧）、dnSpyEx（閲覧 + 編集 + デバッグ。変数を書き換えて実行できる）。難読化されていたら `de4dot` で解除を試す。

### Java / Android

```bash
jadx -d out/ chall.jar                 # Java に逆コンパイル（apk / dex / jar 対応）
jadx-gui app.apk                       # GUI
java -jar cfr.jar Chall.class          # CFR（jadx で失敗する場合）
javap -c -p Chall.class                # バイトコードの逆アセンブル（JDK 付属）
apktool d app.apk -o app_src           # リソース・AndroidManifest・smali を展開
apktool b app_src -o patched.apk       # smali を編集して再ビルド（要署名: apksigner）
```

ネイティブライブラリ（`lib/arm64-v8a/*.so`）は Ghidra で解析、動的には Frida（[dynamic/README.md](../dynamic/README.md#frida_hookjs)）。

### Python

[pyc_tool.py](#pyc_toolpy) を参照。Nuitka（C に変換されたもの）は逆コンパイル不可 → 動的解析・文字列から攻める。

### Go

- Ghidra 10.3 以降は Go の関数名・型を復元できる（11 以降で精度向上）。GoReSym（Mandiant）で関数名を JSON 出力して取り込むことも可
- 文字列は NUL 終端ではなく（ポインタ, 長さ）の組 → strings で連結された長い文字列が出る
- エントリは `main.main`。`runtime.*` はノイズなので飛ばす

### Rust

- `<crate名>::main` を探す。`core::panicking` / `alloc::` はノイズ
- デマングル: `rustfilt`（`cargo install rustfilt`）、Ghidra は自動
- 境界チェック（`panic_bounds_check`）の分岐が多いので、正常系の流れだけ追う

### WebAssembly

```bash
wasm2wat chall.wasm -o chall.wat       # テキスト形式（wabt）
wasm-decompile chall.wasm -o chall.dcmp   # C 風の疑似コード（wabt）
```

Ghidra には `ghidra-wasm-plugin`、ブラウザなら DevTools の Sources でステップ実行可能。

### JavaScript / Electron

```bash
npx asar extract app.asar app_src      # Electron アプリのソース取り出し
npx webcrack obfuscated.js -o out/     # 難読化 JS の解除（obfuscator.io 系）
npx prettier --write out.js            # 整形
```

### Lua / その他

| 対象 | ツール |
|---|---|
| Lua バイトコード（`\x1bLua`） | `unluac`, `luadec` |
| AutoIt exe | AutoIt-Ripper |
| Delphi | IDR (Interactive Delphi Reconstructor) |
| Unity (Mono) | `Assembly-CSharp.dll` を ILSpy |
| Unity (IL2CPP) | Il2CppDumper → Ghidra / IDA に関数名を適用 |
| VB6 | VB Decompiler |
| Mach-O (macOS / iOS) | Ghidra / Hopper、`otool -tV`, `class-dump` |
