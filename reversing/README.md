# 🔁 reversing — リバースエンジニアリング

CTF の Reversing（crackme / keygen / 難読化バイナリ）向けのスクリプトとコマンド集。
解析の段階ごとにディレクトリを分けています。まずこのページで全体の流れをつかみ、詳細は各ディレクトリの README を見てください。

| ディレクトリ | 段階 | 何をするか | 詳細 |
|---|---|---|---|
| [`surface/`](surface/) | 🔍 表層解析 | **実行せずに**ファイルの素性を調べる（形式・アーキ・保護機構・文字列・パック有無・埋め込みファイル） | [surface/README.md](surface/README.md) |
| [`static/`](static/) | 🧩 静的解析 | **実行せずに**中身を読む（逆アセンブル・逆コンパイル・データ抽出・パッチ・言語別デコンパイラ） | [static/README.md](static/README.md) |
| [`dynamic/`](dynamic/) | 🐞 動的解析 | **実行して**挙動を観察する（gdb・ltrace/strace・LD_PRELOAD・Frida・アンチデバッグ回避・他アーキ実行） | [dynamic/README.md](dynamic/README.md) |
| [`solve/`](solve/) | 🧮 ソルバ | 判定ロジックから**入力を逆算**する（angr・Z3・サイドチャネル総当たり） | [solve/README.md](solve/README.md) |

---

## 目次

- [解析の基本フロー](#解析の基本フロー)
- [5 分でわかる使い方（例）](#5-分でわかる使い方例)
- [ツールのインストール](#ツールのインストール)
- [Apple Silicon Mac で Linux バイナリを解析するには](#apple-silicon-mac-で-linux-バイナリを解析するには)
- [アドレスの基準（ツールごとに違う）](#アドレスの基準ツールごとに違う)
- [用途別の逆引き](#用途別の逆引き)
- [スクリプト一覧](#スクリプト一覧)

---

## 解析の基本フロー

```
            ┌──────────────────────────────────────────────────────────────┐
  配布物 ──▶│ 1. 表層解析  surface/triage.sh                                 │
            │    形式・アーキ・stripped?・パック?・言語・flag 文字列そのまま? │
            └───────┬──────────────────────────────────────────────────────┘
                    │ UPX → upx -d / PyInstaller → pyc_tool / .NET → ILSpy …
                    ▼
            ┌──────────────────────────────────────────────────────────────┐
            │ 2. 静的解析  static/ghidra_decompile.sh, r2_analyze.sh         │
            │    main → 判定関数を特定し、入力がどう変換・比較されるか読む   │
            └───────┬───────────────────────────────┬──────────────────────┘
                    │ ロジックが読める               │ 読みにくい / 実行時に決まる値がある
                    ▼                               ▼
            ┌───────────────────────────┐   ┌────────────────────────────────────┐
            │ 4. ソルバ  solve/          │   │ 3. 動的解析  dynamic/               │
            │  z3_template.py で逆算     │◀──│  比較関数の引数を覗く・値をダンプ   │
            │  angr_solve.py で自動探索  │   │  gdb_cmp_hook.py / ld_preload_hook  │
            │  sidechannel_brute.py      │   │  アンチデバッグはパッチ or フック   │
            └───────────────────────────┘   └────────────────────────────────────┘
```

**手を動かす順番の目安**

1. `triage.sh` で全体像。`strings` に flag がそのまま入っていないか、成功/失敗メッセージは何か
2. 動的リンク & 比較関数（strcmp / memcmp）を使っていそうなら、**まず `trace.sh cmp` か `gdb_cmp_hook.py`**。正解文字列がそのまま見えて終わることがある
3. 見えなければ Ghidra で判定関数を読む。比較対象の配列は `extract_bytes.py` で抜き出す
4. 変換が可逆なら Python で逆変換、複雑なら Z3、面倒なら angr に丸投げ
5. 1 文字ずつ比較して早期 return する実装なら `sidechannel_brute.py` が楽

---

## 5 分でわかる使い方（例）

```bash
# 1. 表層解析
bash reversing/surface/triage.sh ./chall
#  → x86-64 PIE / stripped / "Correct!" "Wrong" / ptrace の文字列 … とわかる

# 2. 比較関数を覗く（正解が strcmp に渡っていればここで終わり）
echo 'AAAA' | bash reversing/dynamic/trace.sh cmp ./chall
gdb -q -batch -x reversing/dynamic/gdb_cmp_hook.py ./chall < input.txt

# 3. 逆コンパイルして判定関数を読む
bash reversing/static/ghidra_decompile.sh ./chall      # → chall.c
bash reversing/static/r2_analyze.sh ./chall xref Correct   # "Correct" を参照している関数

# 4. 比較対象のデータを取り出す（Ghidra のアドレスをそのまま使える）
python3 reversing/static/extract_bytes.py ./chall --addr 0x104010 --base 0x100000 -n 32 -f py

# 5. 解く
python3 reversing/solve/angr_solve.py ./chall --find 'Correct' --avoid 'Wrong' --len 32
#  or z3_template.py に判定ロジックを書き写す
```

---

## ツールのインストール

スクリプトの多くは **Python 標準ライブラリのみ**で動きます（`surface/*.py`, `extract_bytes.py`, `patch_bytes.py`, `pyc_tool.py`）。
外部ツールは必要に応じて入れてください。

### Linux（Debian / Ubuntu / Kali）

```bash
sudo apt install -y file binutils gdb gdb-multiarch strace ltrace valgrind \
                    qemu-user upx-ucl python3-venv        # ltrace は x86 系のみパッケージあり
# 他アーキの共有ライブラリ（qemu で動的リンク ELF を動かす場合）
sudo apt install -y libc6-armhf-cross libc6-arm64-cross libc6-mips-cross libc6-riscv64-cross
# radare2（ディストリ版は古い/無いことがあるので公式推奨の方法で）
git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh
```

### macOS（Homebrew）

```bash
brew install binutils radare2 upx qemu       # binutils の objdump は gobjdump という名前で入る
brew install ghidra                          # Ghidra（ヘッドレス用の analyzeHeadless も入る。古い環境では --cask）
# gdb は Apple Silicon 非対応 → Linux コンテナ / VM で（次節参照）
```

### Python パッケージ（venv 推奨）

```bash
python3 -m venv ~/.venv/re && source ~/.venv/re/bin/activate
pip install angr z3-solver frida-tools pwntools
pip install decompyle3 uncompyle6          # Python 3.8 以前の pyc 逆コンパイル
```

> angr は Python のバージョンに敏感です。新しすぎる Python で入らない場合は `uv venv --python 3.12` などで作った環境に入れてください。

### GUI ツール（必要に応じて）

| ツール | 用途 | 入手 |
|---|---|---|
| Ghidra | 逆アセンブル・逆コンパイル（無料・全アーキ） | https://ghidra-sre.org / `brew install ghidra` |
| IDA Free | 逆アセンブル + x86/x64 クラウド逆コンパイル | https://hex-rays.com/ida-free |
| Binary Ninja Free | 逆アセンブル・HLIL | https://binary.ninja/free |
| Cutter | radare2(rizin) の GUI | https://cutter.re |
| x64dbg | Windows デバッガ | https://x64dbg.com |
| ILSpy / dnSpyEx | .NET 逆コンパイル / デバッグ | GitHub |
| jadx | Java / Android 逆コンパイル | `brew install jadx` / GitHub |
| Detect It Easy | パッカー・コンパイラ判定 | GitHub (horsicq/Detect-It-Easy) |

---

## Apple Silicon Mac で Linux バイナリを解析するには

CTF の配布バイナリはほぼ **Linux x86-64 ELF** です。Mac (arm64) では直接実行できません。

| やりたいこと | 方法 |
|---|---|
| 表層・静的解析 | そのまま Mac で OK（`surface/*.py`, Ghidra, `r2`, `extract_bytes.py`, `patch_bytes.py` は形式・アーキに依存しない） |
| 実行するだけ | `docker run --rm -it --platform linux/amd64 -v $PWD:/w -w /w ubuntu bash`（Rosetta で x86-64 が動く） |
| **gdb でデバッグ** | ⚠ `--platform linux/amd64` コンテナでは ptrace が使えず gdb が `Couldn't get CS register` で失敗する<br>→ arm64 コンテナで `qemu-x86_64 -g 1234` + `gdb-multiarch` を使う（[dynamic/README.md](dynamic/README.md#apple-silicon-での-x86-64-デバッグ)） |
| angr / Z3 | Mac ネイティブの Python でも、arm64 コンテナでも動く（angr はバイナリを実行しないので x86-64 でも OK） |

```bash
# 解析用 arm64 Linux コンテナ（gdb / qemu-user / クロス libc 入り）の例
docker run --rm -it --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
  -v "$PWD":/w -w /w debian:trixie bash
apt update && apt install -y gdb gdb-multiarch qemu-user libc6-amd64-cross strace python3
```

---

## アドレスの基準（ツールごとに違う）

PIE バイナリは「どこにロードされるか」が決まっていないため、**ツールごとに表示されるアドレスがずれます**。
スクリプトの `--base` オプションはこの差を吸収するためのものです。

| ツール | PIE ELF のベース | 例: ファイル上 0x11d6 の関数 |
|---|---|---|
| objdump / readelf / nm / radare2 | `0x0` | `0x11d6` |
| Ghidra | `0x100000` | `0x1011d6` |
| IDA | `0x0` | `0x11d6` |
| angr | `0x400000`（`--base` で変更可） | `0x4011d6` |
| gdb（ASLR 無効時） | x86-64: `0x555555554000` / AArch64: `0xaaaaaaaa0000` | `0x5555555551d6` |
| 実行時（ASLR 有効） | 毎回変わる | Frida なら `Process.mainModule.base.add(0x11d6)` |

非 PIE（`No PIE`）のバイナリはどのツールでも同じアドレス（多くは `0x400000` 起点）です。
PE（Windows）は Ghidra / IDA / x64dbg とも ImageBase（例 `0x140000000`）起点で揃います。

```bash
# Ghidra で見つけたアドレスをそのまま使う例
python3 reversing/static/extract_bytes.py ./chall --addr 0x104020 --base 0x100000 -n 32
python3 reversing/static/patch_bytes.py   ./chall --addr 0x1012a5 --base 0x100000 --flip
python3 reversing/solve/angr_solve.py     ./chall --base 0x100000 --find 0x101300 --avoid 0x101310
```

---

## 用途別の逆引き

| やりたいこと / 状況 | 使うもの |
|---|---|
| 何のファイルかわからない | `surface/triage.sh` |
| ELF の保護機構（PIE / RELRO / NX / canary）を知りたい | `surface/elf_info.py`（checksec 相当） |
| Windows exe の import や .NET かどうかを知りたい | `surface/pe_info.py` |
| UTF-16 の文字列 / 独自 base64 テーブルを探したい | `surface/strings_ex.py -i` |
| パックされているか判断したい | `surface/entropy.py`（7.2 以上が続く領域）+ `triage.sh` のヒント |
| バイナリの中に別ファイルが埋まっていそう | `surface/embedded_scan.py -x out/` |
| main を読みたい（シンボルあり） | `static/disasm.sh ./chall main` / `static/r2_analyze.sh ./chall main` |
| stripped で main がわからない | `static/disasm.sh ./chall --entry`（`__libc_start_main` の第 1 引数） |
| 全関数を C で読みたい（GUI なし） | `static/ghidra_decompile.sh ./chall` |
| 「Correct」を出している箇所を知りたい | `static/r2_analyze.sh ./chall xref Correct` |
| 暗号化された flag の配列を取り出したい | `static/extract_bytes.py --sym enc_flag -f py` |
| 判定を無理やり通したい / ptrace チェックを消したい | `static/patch_bytes.py --flip / --ret 1 / --nop` |
| PyInstaller の exe / .pyc | pyinstxtractor → `static/pyc_tool.py info / consts` |
| strcmp に渡る正解文字列を見たい | `dynamic/trace.sh cmp` / `dynamic/gdb_cmp_hook.py` / `dynamic/ld_preload_hook.c` |
| gdb を検知して終了する | `gdb_cmp_hook.py`（ptrace 自動回避）/ `ld_preload_hook.c` / `patch_bytes.py` |
| `srand(time(NULL))` の乱数を再現したい | `dynamic/ld_preload_hook.c`（`FAKE_TIME` / `FAKE_SEED`） |
| ARM / MIPS / RISC-V のバイナリ | `dynamic/qemu_run.sh`（`GDB=1234` でデバッグ） |
| Android / Windows のネイティブ処理をフックしたい | `dynamic/frida_hook.js` |
| 判定ロジックは読めたので逆算したい | `solve/z3_template.py` |
| ロジックを読むのが面倒 / 分岐が多い | `solve/angr_solve.py` |
| 1 文字ずつ比較している | `solve/sidechannel_brute.py` |

---

## スクリプト一覧

> `./snip readme` で各スクリプトのヘッダから自動生成されます。

<!-- SNIPPETS:START -->

### 🔍 reversing/surface — 表層解析

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`elf_info.py`](surface/elf_info.py) | ELF のヘッダ・保護機構（checksec 相当）・セクション（エントロピー付き）・依存ライブラリ・シンボルを表示 | none | `python3 reversing/surface/elf_info.py ./chall [--symbols [main]] [--segments] [--json]` |
| [`embedded_scan.py`](surface/embedded_scan.py) | バイナリ内に埋め込まれたファイル（ELF/PE/ZIP/PNG/gzip/zlib 等）をシグネチャで検出・切り出し（binwalk 簡易版） | none | `python3 reversing/surface/embedded_scan.py ./chall [-x ./carved]` |
| [`entropy.py`](surface/entropy.py) | ファイルをブロックごとにエントロピー計算してグラフ表示（パック・暗号化・圧縮データ領域の発見） | none | `python3 reversing/surface/entropy.py ./chall [-b 1024] [--threshold 7.2]` |
| [`pe_info.py`](surface/pe_info.py) | PE (exe/dll) のヘッダ・保護機構・セクション（エントロピー付き）・インポート/エクスポート・TLS・PDB パス・オーバーレイを表示 | none | `python3 reversing/surface/pe_info.py ./chall.exe [--imports] [--exports]` |
| [`strings_ex.py`](surface/strings_ex.py) | strings の強化版（ASCII + UTF-16LE/BE/UTF-32、オフセット表示、flag/URL/成功失敗メッセージ/base64 テーブル等の分類） | none | `python3 reversing/surface/strings_ex.py ./chall --interesting` |
| [`triage.sh`](surface/triage.sh) | リバーシング問題の最初の一手（file・ハッシュ・ELF/PE 情報・言語/パッカー判定・flag/注目文字列・エントロピーを一括表示） | file, python3（strings / upx / otool があれば追加情報） | `bash reversing/surface/triage.sh ./chall` |

### 🧩 reversing/static — 静的解析・パッチ

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`DecompileAll.java`](static/DecompileAll.java) | Ghidra ヘッドレス用ポストスクリプト（全関数 or 名前一致の関数を逆コンパイルして 1 つの C ファイルに出力） | Ghidra 10 以上（ghidra_decompile.sh から呼ばれる） | `analyzeHeadless /tmp/proj p -import ./chall -scriptPath reversing/static -postScript DecompileAll.java out.c [filter] -deleteProject` |
| [`disasm.sh`](static/disasm.sh) | objdump ラッパー（Intel 記法で関数/アドレス範囲を逆アセンブル、関数一覧、stripped バイナリの main 特定） | objdump（GNU binutils または llvm-objdump）, nm | `bash reversing/static/disasm.sh ./chall [main\|0x401136\|--list\|--entry\|--all] [len=0x100]` |
| [`extract_bytes.py`](static/extract_bytes.py) | ELF/PE の仮想アドレス・シンボル名・ファイルオフセットからデータを抜き出し C 配列/Python リスト/u32 配列等に整形（暗号化テーブルの取り出し用） | none | `python3 reversing/static/extract_bytes.py ./chall --sym enc_flag -f py` |
| [`ghidra_decompile.sh`](static/ghidra_decompile.sh) | Ghidra をヘッドレス実行して全関数（または指定関数）を C 言語に逆コンパイルしファイル出力（GUI 不要） | Ghidra（analyzeHeadless）, Java 17+ | `bash reversing/static/ghidra_decompile.sh ./chall [out.c] [関数名フィルタ]` |
| [`patch_bytes.py`](static/patch_bytes.py) | バイナリパッチ（VA/オフセット指定でバイト書換・NOP 埋め・条件分岐反転・常に jmp・即 return）とバイト列検索 | none | `python3 reversing/static/patch_bytes.py ./chall --addr 0x4012a5 --flip -o ./chall.patched` |
| [`pyc_tool.py`](static/pyc_tool.py) | .pyc の Python バージョン判定・ヘッダ修復（pyinstxtractor 出力向け）・逆アセンブル/定数一覧（同バージョンの Python で実行時） | none（逆コンパイルは pycdc / decompyle3 / uncompyle6 を別途） | `python3 reversing/static/pyc_tool.py info chall.pyc` |
| [`r2_analyze.sh`](static/r2_analyze.sh) | radare2 を非対話で実行して定番の解析結果を出す（情報・関数一覧・main 逆アセ/疑似 C・文字列・文字列の参照元・呼び出し関係） | radare2（R2=rizin で rizin も可。dec は r2ghidra / r2dec があれば使う） | `bash reversing/static/r2_analyze.sh ./chall [info\|funcs\|main\|func <名前\|0xaddr>\|dec <名前>\|strings\|xref <文字列>\|calls <名前>]` |

### 🐞 reversing/dynamic — 動的解析

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`frida_hook.js`](dynamic/frida_hook.js) | Frida フックスクリプト（strcmp/memcmp 等の引数ログ、ptrace/IsDebuggerPresent 回避、任意アドレスでのレジスタ表示・戻り値書換） | frida-tools（pip install frida-tools）。Frida 16 / 17 両対応 | `frida -q -l reversing/dynamic/frida_hook.js -f ./chall` |
| [`gdb_cmp_hook.py`](dynamic/gdb_cmp_hook.py) | gdb 用 Python スクリプト: strcmp/strncmp/memcmp/strstr 等の引数を止めずにログ出力し、ptrace アンチデバッグも自動回避 | gdb（Python 対応ビルド。x86-64 / i386 / AArch64 / ARM / RISC-V / MIPS） | `gdb -q -batch -x reversing/dynamic/gdb_cmp_hook.py --args ./chall [args]` |
| [`ld_preload_hook.c`](dynamic/ld_preload_hook.c) | LD_PRELOAD 用フックライブラリ（strcmp/memcmp 等の引数ログ、ptrace アンチデバッグ回避、sleep 無効化、time/rand の固定） | gcc（対象が動的リンクされた Linux バイナリであること） | `gcc -shared -fPIC -O2 -o hook.so reversing/dynamic/ld_preload_hook.c -ldl && LD_PRELOAD=./hook.so ./chall` |
| [`qemu_run.sh`](dynamic/qemu_run.sh) | ARM/AArch64/MIPS/RISC-V/PowerPC/x86 など他アーキの Linux ELF を qemu-user で実行（アーキ自動判定・sysroot 自動選択・gdb 接続待ち） | qemu-user（apt install qemu-user / qemu-user-static）、動的リンクなら libc6-<arch>-cross | `bash reversing/dynamic/qemu_run.sh ./chall_arm [args]   /   GDB=1234 bash reversing/dynamic/qemu_run.sh ./chall_arm` |
| [`trace.sh`](dynamic/trace.sh) | ltrace / strace の定番オプションをモード指定で実行（ライブラリ呼び出し・比較関数・システムコール・ファイル・ネットワーク） | ltrace, strace（Linux） | `echo 'AAAA' \| bash reversing/dynamic/trace.sh cmp ./chall [args]` |

### 🧮 reversing/solve — シンボリック実行・ソルバ

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`angr_solve.py`](solve/angr_solve.py) | angr のシンボリック実行で「成功メッセージに到達する入力」を自動探索（stdin / argv 入力、文字列 or アドレスで find/avoid 指定） | angr（pip install angr。Python 3.10〜3.12 推奨） | `python3 reversing/solve/angr_solve.py ./chall --find Correct --avoid Wrong --len 32` |
| [`sidechannel_brute.py`](solve/sidechannel_brute.py) | 実行命令数のサイドチャネルで flag を 1 文字ずつ総当たり（先頭から比較して不一致で抜ける実装に有効。perf / valgrind） | perf（linux-tools）または valgrind | `python3 reversing/solve/sidechannel_brute.py ./chall --len 19 --prefix 'flag{' --success Correct` |
| [`z3_template.py`](solve/z3_template.py) | Z3 で「逆コンパイルした判定ロジック」を制約として書いて flag を解くテンプレート（XOR・加算・ローテート・連立式・全解列挙の例つき） | z3-solver（pip install z3-solver） | `python3 reversing/solve/z3_template.py [--all]` |

<!-- SNIPPETS:END -->
