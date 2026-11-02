# 🔍 reversing/surface — 表層解析

**プログラムを実行せずに**、ファイルの素性（形式・アーキテクチャ・保護機構・文字列・パックの有無・埋め込みファイル）を調べる段階です。
ここで「何で作られた何なのか」を把握すると、次に使うべきツール（Ghidra / ILSpy / pyc 逆コンパイラ / upx -d …）が決まります。

← [reversing/README.md（全体の流れ）](../README.md) ／ 次の段階: [static/（静的解析）](../static/README.md)

---

## 目次

- [最初の一手](#最初の一手)
- [スクリプト一覧](#スクリプト一覧)
- [スクリプトの詳しい使い方](#スクリプトの詳しい使い方)
  - [triage.sh](#triagesh) / [elf_info.py](#elf_infopy) / [pe_info.py](#pe_infopy) / [strings_ex.py](#strings_expy) / [entropy.py](#entropypy) / [embedded_scan.py](#embedded_scanpy)
- [外部コマンド集](#外部コマンド集)
- [出力の読み方・判断の目安](#出力の読み方判断の目安)

---

## 最初の一手

```bash
bash reversing/surface/triage.sh ./chall
```

`file` → ハッシュ → ELF/PE 情報 → 言語・パッカー判定 → flag/注目文字列 → エントロピー → 埋め込みファイル、を一度に表示します。
気になった項目を下の個別スクリプトで深掘りしてください。

---

## スクリプト一覧

<!-- SNIPPETS:START -->

### 🔍 reversing/surface — 表層解析

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`elf_info.py`](elf_info.py) | ELF のヘッダ・保護機構（checksec 相当）・セクション（エントロピー付き）・依存ライブラリ・シンボルを表示 | none | `python3 reversing/surface/elf_info.py ./chall [--symbols [main]] [--segments] [--json]` |
| [`embedded_scan.py`](embedded_scan.py) | バイナリ内に埋め込まれたファイル（ELF/PE/ZIP/PNG/gzip/zlib 等）をシグネチャで検出・切り出し（binwalk 簡易版） | none | `python3 reversing/surface/embedded_scan.py ./chall [-x ./carved]` |
| [`entropy.py`](entropy.py) | ファイルをブロックごとにエントロピー計算してグラフ表示（パック・暗号化・圧縮データ領域の発見） | none | `python3 reversing/surface/entropy.py ./chall [-b 1024] [--threshold 7.2]` |
| [`pe_info.py`](pe_info.py) | PE (exe/dll) のヘッダ・保護機構・セクション（エントロピー付き）・インポート/エクスポート・TLS・PDB パス・オーバーレイを表示 | none | `python3 reversing/surface/pe_info.py ./chall.exe [--imports] [--exports]` |
| [`strings_ex.py`](strings_ex.py) | strings の強化版（ASCII + UTF-16LE/BE/UTF-32、オフセット表示、flag/URL/成功失敗メッセージ/base64 テーブル等の分類） | none | `python3 reversing/surface/strings_ex.py ./chall --interesting` |
| [`triage.sh`](triage.sh) | リバーシング問題の最初の一手（file・ハッシュ・ELF/PE 情報・言語/パッカー判定・flag/注目文字列・エントロピーを一括表示） | file, python3（strings / upx / otool があれば追加情報） | `bash reversing/surface/triage.sh ./chall` |

<!-- SNIPPETS:END -->

---

## スクリプトの詳しい使い方

### triage.sh

```bash
bash reversing/surface/triage.sh <binary>
```

| セクション | 内容 | 使っているもの |
|---|---|---|
| file | 形式・アーキ・リンク方式・stripped か | `file`, `sha256sum`/`shasum` |
| ELF / PE 情報 | ヘッダ・保護機構・依存ライブラリ・ヒント | `elf_info.py` / `pe_info.py` |
| 言語・パッカー | UPX / Go / Rust / PyInstaller / .NET / Delphi / Electron / アンチデバッグの兆候 | 文字列シグネチャ |
| flag / 注目文字列 | flag 形式・成功失敗メッセージ・URL・base64 テーブル等 | `strings_ex.py -i` |
| エントロピー | 圧縮・暗号化・パックされた領域 | `entropy.py --summary` |
| 埋め込みファイル | 中に別の ELF / ZIP / PNG 等 | `embedded_scan.py` |

Mach-O の場合は `otool` の結果、ZIP 系（jar/apk）の場合は中身の一覧を表示します。

---

### elf_info.py

`readelf` + `checksec` + `nm` の要点を **Python 標準ライブラリだけ**で出します（macOS でも Linux バイナリを解析可能）。

```bash
python3 reversing/surface/elf_info.py ./chall               # ヘッダ・保護機構・セクション
python3 reversing/surface/elf_info.py ./chall -s            # + 関数/変数シンボル・インポート関数
python3 reversing/surface/elf_info.py ./chall -s check      # シンボル名で絞り込み
python3 reversing/surface/elf_info.py ./chall -l            # + セグメント（プログラムヘッダ）
python3 reversing/surface/elf_info.py ./chall --json        # JSON（他スクリプトから使う用）
```

出力例（抜粋）:

```
== protections (checksec)
  relro     : Partial RELRO（GOT 書き換え可）
  canary    : なし
  nx        : NX 有効
  pie       : No PIE（アドレス固定）
  stripped  : No（シンボルあり）
  linking   : dynamic

== symbols (27)
  0x0000004011d6     171  FUNC   check          ← 自作関数。サイズが大きいものから読む
  0x000000401281     317  FUNC   main
  0x000000404070      19  OBJECT enc_flag       ← 比較対象のデータっぽい → static/extract_bytes.py
```

| 項目 | 意味と Reversing での使い道 |
|---|---|
| PIE | 有効だとアドレスがツールごとにずれる（[アドレスの基準](../README.md#アドレスの基準ツールごとに違う)） |
| stripped | Yes なら関数名なし → `static/disasm.sh --entry` で main を推定、Ghidra の自動解析に頼る |
| linking: static | libc 関数も中に入っている → ltrace / LD_PRELOAD が効かない。Ghidra で libc 関数を識別（FID）|
| canary / RELRO / NX | 主に Pwn 向けの情報。Reversing ではあまり気にしなくてよい |
| entropy 7.0 以上 | そのセクションが圧縮・暗号化されている |
| セクションヘッダなし | `sstrip` やパッカー。セグメント（`-l`）で見る |

---

### pe_info.py

Windows の exe / dll を `pefile` なしで解析します。

```bash
python3 reversing/surface/pe_info.py ./chall.exe            # 概要 + 注目 API
python3 reversing/surface/pe_info.py ./chall.exe -i         # インポート関数を全部表示
python3 reversing/surface/pe_info.py ./lib.dll -e           # エクスポート関数
```

表示内容: PE32/PE32+・アーキ・サブシステム（GUI/CUI）・ImageBase・エントリポイント・ビルド時刻・ASLR/DEP/CFG・PDB パス・セクション（エントロピー / W+X 検出）・インポート・注目 API の分類・ヒント。

| ヒント | 意味 / 次の一手 |
|---|---|
| `.NET アセンブリ` | C# に戻せる。ILSpy / dnSpyEx / `ilspycmd` → [static/README.md](../static/README.md#net-c) |
| `TLS コールバック` | エントリより先に実行される関数。アンチデバッグが仕込まれやすい（MinGW は標準で持つ） |
| `UPX0` 等のセクション名 | パッカー。`upx -d` で展開 |
| `W+X` セクション | 実行時に自己書き換え / 展開する可能性 |
| `raw=0` で vsize が大きい | 実行時に中身が書き込まれる（UPX0 など） |
| オーバーレイ | PE の後ろに付加データ（インストーラ・埋め込みファイル）→ `embedded_scan.py` |
| COFF シンボルテーブル | MinGW の未 strip ビルド。関数名が残っている（Ghidra で表示される） |
| 注目 API: anti-debug | `IsDebuggerPresent` 等 → [dynamic/README.md](../dynamic/README.md#アンチデバッグ回避) |
| 注目 API: crypto | `CryptDecrypt` / `BCrypt*` → 鍵・IV を動的に取る |

---

### strings_ex.py

GNU `strings` の強化版です。Windows の UTF-16 文字列（`strings -el` が必要なもの）や Linux の `wchar_t`（UTF-32）、独自 base64 テーブルも拾います。

```bash
python3 reversing/surface/strings_ex.py ./chall                 # ASCII + UTF-16LE（オフセット付き）
python3 reversing/surface/strings_ex.py ./chall -i              # 分類に当てはまるものだけ（カテゴリ付き）
python3 reversing/surface/strings_ex.py ./chall -g 'key|pass'   # 正規表現で絞り込み
python3 reversing/surface/strings_ex.py ./chall -e all -n 6     # 全エンコーディング、6 文字以上
cat dump.bin | python3 reversing/surface/strings_ex.py          # stdin から
```

| カテゴリ | 拾うもの |
|---|---|
| `flag` | `xxx{...}` 形式、flag / ctf を含む |
| `message` | Correct / Wrong / password / Enter / serial など（判定箇所の目印） |
| `url` / `path` | 通信先・ファイルパス |
| `anti-debug` | ptrace / TracerPid / IsDebuggerPresent / gdb / frida |
| `crypto` | AES / RC4 / TEA / SHA / CRC32 などの名前 |
| `format` | `%s` `%d` など printf 書式（入出力の箇所） |
| `b64-table(custom?)` | 64 文字の重複なし英数字列 = **base64 の変換テーブル**。標準と違えば独自 base64 |

> オフセットは**ファイルオフセット**です。仮想アドレスに変換するには `elf_info.py` のセクション表（offset と addr の差）を使うか、`static/r2_analyze.sh strings` を使ってください。

---

### entropy.py

ブロックごとのエントロピー（0〜8）をバーグラフで表示します。

```bash
python3 reversing/surface/entropy.py ./chall               # 全ブロック（約 64 行）
python3 reversing/surface/entropy.py ./chall -b 4096       # ブロックサイズ指定
python3 reversing/surface/entropy.py ./chall --summary     # 全体値と high 領域だけ
```

| 値 | 典型的な中身 |
|---|---|
| 0〜1 | ゼロ埋め・パディング |
| 4〜6 | 機械語・テキスト・通常のデータ |
| 6.5〜7.2 | 圧縮されていない画像・密なテーブル |
| **7.2〜8** | **圧縮・暗号化・パック済み**（UPX / zlib / AES で暗号化された埋め込みデータ） |

---

### embedded_scan.py

binwalk の簡易版です。ELF / PE / ZIP / PNG / JPEG / gzip / bzip2 / xz / 7z / RAR / PDF / SQLite / DEX / Mach-O / PyInstaller cookie と、**展開できる zlib ストリーム**を検出します。

```bash
python3 reversing/surface/embedded_scan.py ./chall               # 検出のみ
python3 reversing/surface/embedded_scan.py ./chall -x ./carved   # 切り出し（zlib は展開結果も .inflated で保存）
python3 reversing/surface/embedded_scan.py big.bin --no-zlib     # 大きいファイルで遅い場合
```

```
    offset         end  type
       0x0      0x4118  ELF  (ファイル自身)
    0x4118      0x4134  zlib stream (展開後 85 bytes)
    0x41d2      0x4217  PNG
[+] carved/00004118.zlib (28 bytes) + .inflated
```

終端が計算できる形式（PNG / JPEG / ZIP / gzip / zlib / RIFF）は正確に、それ以外は次の検出位置かファイル末尾まで切り出します。

---

## 外部コマンド集

### file — 形式の判定

```bash
file ./chall
# ELF 64-bit LSB pie executable, x86-64, dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, ..., stripped
file -b ./chall          # ファイル名を出さない
file -z ./chall.gz       # 圧縮ファイルの中身も判定
```

読むポイント: `ELF 64-bit` / `PE32+` / `Mach-O`、`x86-64` / `ARM aarch64` / `MIPS`、`pie executable`、`statically linked`、`stripped`、`Go BuildID`。

### strings — 文字列

```bash
strings -a -n 6 ./chall          # 全体から 6 文字以上（-a は古い binutils で必要）
strings -t x ./chall             # 16 進オフセット付き
strings -el ./chall.exe          # UTF-16LE（Windows のワイド文字列）
strings ./chall | grep -iE 'flag|ctf|correct|wrong|pass'
```

### xxd / hexdump / od — 16 進ダンプ

```bash
xxd ./chall | head                    # 先頭を確認（マジックナンバー）
xxd -s 0x3070 -l 32 ./chall           # オフセット 0x3070 から 32 バイト
xxd -p ./chall | tr -d '\n'           # 素の hex 文字列
xxd -r -p hex.txt > out.bin           # hex → バイナリ
hexdump -C ./chall | less             # BSD/macOS でも使える
od -An -tx1 -N4 ./chall               # 先頭 4 バイトだけ
```

主なマジックナンバー: `7f 45 4c 46`=ELF, `4d 5a`=PE(MZ), `cf fa ed fe`=Mach-O 64, `ca fe ba be`=Java class / Mach-O fat, `50 4b 03 04`=ZIP(jar/apk), `64 65 78 0a`=DEX, `00 61 73 6d`=WebAssembly, `XX XX 0d 0a`=pyc

### readelf — ELF の構造（Linux / binutils）

```bash
readelf -h ./chall        # ELF ヘッダ（エントリポイント・アーキ・種別）
readelf -l ./chall        # プログラムヘッダ（セグメント・INTERP・GNU_STACK）
readelf -S ./chall        # セクション一覧
readelf -s ./chall        # シンボル（.symtab + .dynsym）
readelf --dyn-syms ./chall    # 動的シンボル（stripped でも残る import 関数名）
readelf -d ./chall        # 動的セクション（NEEDED ライブラリ・RUNPATH・BIND_NOW）
readelf -r ./chall        # リロケーション（GOT のどこに何の関数が入るか）
readelf -x .rodata ./chall    # セクションを hex ダンプ
readelf -p .rodata ./chall    # セクション内の文字列
readelf -n ./chall        # ノート（Build ID / Go の build ID）
```

### objdump / nm — セクション・シンボル

```bash
objdump -f ./chall              # 形式とエントリポイント（start address）
objdump -h ./chall              # セクションヘッダ
objdump -p ./chall              # NEEDED などプライベートヘッダ（ELF / PE 両対応）
objdump -T ./chall              # 動的シンボル
objdump -s -j .rodata ./chall   # セクションの hex + ASCII
nm -C ./chall                   # シンボル（-C で C++ デマングル）
nm -D ./chall                   # 動的シンボル
nm --defined-only ./chall | grep ' T '   # 自作関数（T = text セクションの関数）
```

逆アセンブルは [static/README.md](../static/README.md) を参照。

### ldd ⚠ — 依存ライブラリ

```bash
ldd ./chall                         # ⚠ 環境によっては実際にバイナリを実行するので、怪しいファイルには使わない
readelf -d ./chall | grep NEEDED    # 安全な代替
objdump -p ./chall | grep NEEDED    # 安全な代替
```

### checksec（pwntools）

```bash
pip install pwntools
checksec ./chall      # または pwn checksec ./chall
```

`elf_info.py` でも同じ情報が出ます（pwntools 不要）。

### rabin2（radare2 付属）— 何でも 1 コマンド

```bash
rabin2 -I ./chall     # 概要（arch / bits / canary / nx / pic / stripped / lang）
rabin2 -e ./chall     # エントリポイント
rabin2 -i ./chall     # インポート
rabin2 -E ./chall     # エクスポート
rabin2 -S ./chall     # セクション（r2 内なら iS entropy でエントロピー付き）
rabin2 -z ./chall     # データセクションの文字列（仮想アドレス付き）
rabin2 -zz ./chall    # ファイル全体の文字列
rabin2 -l ./chall     # リンクされたライブラリ
```

ELF / PE / Mach-O / DEX など形式を問わず同じオプションで使えます。

### binwalk — 埋め込みファイル

```bash
binwalk ./firmware.bin          # 検出
binwalk -e ./firmware.bin       # 既知形式を展開（_firmware.bin.extracted/）
binwalk -Me ./firmware.bin      # 再帰的に展開
binwalk -E ./firmware.bin       # エントロピーグラフ
binwalk --dd='.*' ./file        # 全シグネチャを生で切り出し
```

binwalk がない環境では `embedded_scan.py` で代用できます。

### upx — パッカー

```bash
upx -t ./chall        # UPX でパックされているか確認
upx -d ./chall -o ./chall.unpacked   # 展開
```

`upx -d` が失敗する場合はマジック `UPX!` が書き換えられている（改造 UPX）ことが多い → hex エディタで `UPX!` に戻すか、実行して展開後のメモリをダンプ（[dynamic/README.md](../dynamic/README.md#パッカーの手動展開)）。

### その他

| コマンド | 用途 |
|---|---|
| `diec ./chall` | Detect It Easy の CLI。コンパイラ・パッカー・言語を判定 |
| `exiftool ./chall.exe` | PE のバージョン情報・作成者・タイムスタンプ |
| `otool -hv -L ./chall`（macOS） | Mach-O のヘッダ・依存ライブラリ |
| `codesign -dvvv ./chall`（macOS） | 署名情報 |
| `unzip -l app.apk` / `unzip -l x.jar` | APK / JAR の中身 |
| `python3 -m zipfile -l x.jar` | unzip がない環境 |
| `sha256sum ./chall` | ハッシュ（VirusTotal 検索用 → `soc/hash_file.py --vt`） |

---

## 出力の読み方・判断の目安

| 表層解析でわかったこと | 次にやること |
|---|---|
| strings に flag がそのまま | 終了（ただし偽 flag のこともあるので判定を通るか確認） |
| `Correct` / `Wrong` の文字列がある | `static/r2_analyze.sh xref Correct` で判定箇所へ |
| 動的リンク + strcmp / memcmp を import | `dynamic/trace.sh cmp` で比較を覗く |
| stripped | `static/disasm.sh --entry` / Ghidra の自動解析 |
| UPX | `upx -d` → もう一度 triage |
| エントロピーが高い + import が少ない | 独自パッカー → 動的に展開してダンプ |
| .NET | ILSpy（C# がほぼそのまま読める） |
| PyInstaller | pyinstxtractor → `static/pyc_tool.py` |
| Go | Ghidra 11+ / GoReSym で関数名を復元してから読む |
| ARM / MIPS / RISC-V | Ghidra で静的解析、`dynamic/qemu_run.sh` で実行 |
| ptrace / IsDebuggerPresent | 動的解析前にアンチデバッグ回避を準備 |
| 埋め込み ELF / ZIP | `embedded_scan.py -x` で取り出して再度 triage |
