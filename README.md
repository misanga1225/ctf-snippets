# ctf-snippets

CTF（ネットワーク / リバースエンジニアリング / エンコード）と NOC/SOC で使うスクリプトをまとめたスニペット集。

- **言語**: Python 3（メイン）+ Bash（tshark / nmap / objdump / radare2 / Ghidra などのラッパー）+ C / JavaScript / Java（フック・Ghidra スクリプト）
- **依存**: 基本は Python 標準ライブラリのみ。外部コマンドが必要なものは各スクリプトの `@deps` と各分野の README に記載
- **使い方**: 各スクリプトは単体で実行でき、入力をパイプでつなげられます
- **検索**: 付属の `snip` コマンドで一覧・キーワード検索・使い方表示ができます
- **ドキュメント**: このページは全体の案内です。**各スクリプトの詳しい使い方・関連コマンドは分野ごとの README** にあります

---

## 目次

- [分野別ドキュメント](#分野別ドキュメント)
- [セットアップ](#セットアップ)
- [クイックスタート](#クイックスタート)
- [ディレクトリ構成](#ディレクトリ構成)
- [スクリプト一覧](#スクリプト一覧)
- [用途別の逆引き](#用途別の逆引き)
- [snip コマンド](#snip-コマンド)
- [スニペットの追加方法](#スニペットの追加方法)

---

## 分野別ドキュメント

| 分野 | 内容 | ドキュメント |
|---|---|---|
| 🔤 encoding | base64 / hex / XOR / ROT / URL の変換、多段エンコードの自動判定 | [encoding/README.md](encoding/README.md) |
| 🌐 network | pcap 解析（tshark）、偵察・サブネット計算 | [network/README.md](network/README.md) |
| 　├ 📦 pcap | HTTP ファイル抽出・認証情報・DNS/ICMP 隠しデータ・USB キーボード | [network/pcap/README.md](network/pcap/README.md) |
| 　└ 🛰️ recon | nmap プリセット・CIDR 計算 | [network/recon/README.md](network/recon/README.md) |
| 🔁 reversing | リバースエンジニアリング（解析の流れ・ツールの導入・アドレスの基準） | [reversing/README.md](reversing/README.md) |
| 　├ 🔍 surface | 表層解析: ELF/PE 情報・checksec・strings・エントロピー・埋め込みファイル | [reversing/surface/README.md](reversing/surface/README.md) |
| 　├ 🧩 static | 静的解析: objdump・radare2・Ghidra ヘッドレス・データ抽出・パッチ・pyc | [reversing/static/README.md](reversing/static/README.md) |
| 　├ 🐞 dynamic | 動的解析: gdb・ltrace/strace・LD_PRELOAD・Frida・qemu・アンチデバッグ回避 | [reversing/dynamic/README.md](reversing/dynamic/README.md) |
| 　└ 🧮 solve | ソルバ: angr・Z3・サイドチャネル総当たり | [reversing/solve/README.md](reversing/solve/README.md) |
| 🛡️ soc | ログ解析・IOC 抽出/defang・ハッシュ・疎通確認・whois | [soc/README.md](soc/README.md) |

---

## セットアップ

```bash
git clone <this-repo> ~/src/ctf-snippets   # 置き場所は任意
cd ~/src/ctf-snippets

# snip をどこからでも使えるようにする（clone したディレクトリ内で実行）
# $(pwd) は実行時に実際のパスへ展開されるので、置き場所が違っても正しく登録される
echo "export PATH=\"$(pwd):\$PATH\"" >> ~/.zshrc
source ~/.zshrc                 # 今のシェルにも反映（新しいターミナルなら不要）
snip list                       # 動作確認

# pcap 系スクリプトを使う場合は tshark を入れる
brew install wireshark          # macOS
# sudo apt install tshark       # Debian / Ubuntu / Kali

# 任意の Python パッケージ（scapy / angr / z3 / frida など）
pip install -r requirements.txt
```

動作要件: Python 3.8 以上、Bash。pcap 系は tshark 4.x で動作確認済みです。
リバースエンジニアリング用ツール（gdb / radare2 / Ghidra / qemu など）の導入は [reversing/README.md](reversing/README.md#ツールのインストール) を参照してください。

---

## クイックスタート

```bash
# 何があるか探す
snip list                 # 全スクリプト一覧
snip list reversing       # 分野で絞る
snip search base64        # キーワード検索（複数語は AND）
snip show xor             # 使い方・依存を表示
snip show xor --cat       # 本文を出力（別環境へコピペしたいとき）

# エンコード: パイプでつなぐ（base64 → XOR(0x42) の順で復号）
echo 'JC4jJTk6Pw==' | encoding/b64.py -d | encoding/xor.py -k 0x42
encoding/auto_decode.py 'NjY2YzYxNjc3Yjc4N2Q='    # 多段エンコードの自動判定 => [base64 -> hex] flag{x}

# pcap: まず全体像
bash network/pcap/pcap_summary.sh capture.pcap

# リバーシング: 表層解析 → 比較関数を覗く → 自動で解く
bash reversing/surface/triage.sh ./chall
echo 'AAAA' | bash reversing/dynamic/trace.sh cmp ./chall
python3 reversing/solve/angr_solve.py ./chall --find Correct --avoid Wrong --len 32

# どこからでもスクリプトのパスを取得
python3 "$(snip path dns_exfil)" capture.pcap -d evil.com
```

---

## ディレクトリ構成

```
ctf-snippets/
├── README.md                   ← このファイル（全体の案内）
├── snip                        スクリプトの一覧・検索・表示 CLI / README の一覧表を自動生成
├── requirements.txt            任意の Python 依存
│
├── encoding/                   エンコード / デコード          → encoding/README.md
│   ├── auto_decode.py          多段エンコードの自動判定
│   ├── b64.py / hexconv.py / rot.py / urlenc.py / xor.py
│
├── network/                    ネットワーク                   → network/README.md
│   ├── pcap/                   pcap 解析（tshark 利用）       → network/pcap/README.md
│   │   ├── pcap_summary.sh     まず最初に実行: 全体像の把握
│   │   ├── extract_http.sh / follow_tcp.sh / creds_sniff.sh
│   │   ├── dns_queries.sh / dns_exfil.py / icmp_data.py / usb_keyboard.py
│   └── recon/                  偵察・ネットワーク計算         → network/recon/README.md
│       ├── nmap_quick.sh / subnet_calc.py
│
├── reversing/                  リバースエンジニアリング       → reversing/README.md
│   ├── surface/                表層解析                       → reversing/surface/README.md
│   │   ├── triage.sh           まず最初に実行: 全体像の把握
│   │   ├── elf_info.py / pe_info.py / strings_ex.py / entropy.py / embedded_scan.py
│   ├── static/                 静的解析・パッチ               → reversing/static/README.md
│   │   ├── disasm.sh / r2_analyze.sh / ghidra_decompile.sh + DecompileAll.java
│   │   ├── extract_bytes.py / patch_bytes.py / pyc_tool.py
│   ├── dynamic/                動的解析                       → reversing/dynamic/README.md
│   │   ├── trace.sh / gdb_cmp_hook.py / ld_preload_hook.c / frida_hook.js / qemu_run.sh
│   └── solve/                  シンボリック実行・ソルバ       → reversing/solve/README.md
│       ├── angr_solve.py / z3_template.py / sidechannel_brute.py
│
└── soc/                        NOC/SOC 運用・ログ解析         → soc/README.md
    ├── access_log_stats.py / auth_log_bruteforce.py / ioc_extract.py / defang.py
    └── hash_file.py / port_check.py / whois_lookup.sh
```

---

## スクリプト一覧

> この節と各分野 README の一覧表は `./snip readme` で各スクリプトのヘッダから自動生成されます。手で編集しないでください。
> 依存コマンド・使用例は各分野の README の表にあります。

<!-- SNIPPETS:START -->

### 🔤 encoding — エンコード / デコード（詳細: [encoding/README.md](encoding/README.md)）

| スクリプト | 用途 |
|---|---|
| [`auto_decode.py`](encoding/auto_decode.py) | 多段エンコードを自動判定してデコード（CyberChef Magic 簡易版、flag 形式を検出） |
| [`b64.py`](encoding/b64.py) | base64 / base32 / base85 / ascii85 / base58 のエンコード・デコード |
| [`hexconv.py`](encoding/hexconv.py) | hex / bytes / 整数 / 2進数 / 10進バイト列の相互変換 |
| [`rot.py`](encoding/rot.py) | ROT13 / ROT-N / ROT47 / Caesar 全シフト総当たり |
| [`urlenc.py`](encoding/urlenc.py) | URL エンコード / デコード（多重エンコードの完全デコード対応） |
| [`xor.py`](encoding/xor.py) | XOR（単一/複数バイト鍵）、単一バイト鍵の総当たり、既知平文からの鍵推定 |

### 📦 network/pcap — パケットキャプチャ解析（詳細: [network/pcap/README.md](network/pcap/README.md)）

| スクリプト | 用途 |
|---|---|
| [`creds_sniff.sh`](network/pcap/creds_sniff.sh) | 平文認証情報の抽出（FTP/Telnet/HTTP Basic/HTTP POST/POP/IMAP/SMTP AUTH/NTLM） |
| [`dns_exfil.py`](network/pcap/dns_exfil.py) | DNS トンネル/サブドメインに埋め込まれたデータを結合・復元（hex/base32/base64 自動試行） |
| [`dns_queries.sh`](network/pcap/dns_queries.sh) | DNS クエリ名・レコード種別・応答を一覧化（ユニーク/出現回数順） |
| [`extract_http.sh`](network/pcap/extract_http.sh) | HTTP リクエスト一覧を表示し、転送ファイル（HTTP/SMB/FTP-DATA 等のオブジェクト）を抽出 |
| [`follow_tcp.sh`](network/pcap/follow_tcp.sh) | 全 TCP/UDP ストリームを個別ファイルにダンプ（Follow TCP Stream の一括版） |
| [`icmp_data.py`](network/pcap/icmp_data.py) | ICMP ペイロードを結合して隠しデータを抽出（1 パケット 1 バイト型・TTL/ID 埋め込み型にも対応） |
| [`pcap_summary.sh`](network/pcap/pcap_summary.sh) | pcap の全体像を把握（プロトコル階層・IP 会話・TCP 会話・HTTP ホスト・DNS 統計） |
| [`usb_keyboard.py`](network/pcap/usb_keyboard.py) | USB HID キーボードの打鍵データを pcap から復元（Shift・Backspace 対応） |

### 🛰️ network/recon — 偵察・ネットワーク計算（詳細: [network/recon/README.md](network/recon/README.md)）

| スクリプト | 用途 |
|---|---|
| [`nmap_quick.sh`](network/recon/nmap_quick.sh) | nmap の定番スキャンプリセット（全ポート高速発見 → 開いたポートだけ詳細スキャン） |
| [`subnet_calc.py`](network/recon/subnet_calc.py) | CIDR 計算（ネットワーク/ブロードキャスト/ホスト範囲/包含判定/サブネット分割） |

### 🔍 reversing/surface — 表層解析（詳細: [reversing/surface/README.md](reversing/surface/README.md)）

| スクリプト | 用途 |
|---|---|
| [`elf_info.py`](reversing/surface/elf_info.py) | ELF のヘッダ・保護機構（checksec 相当）・セクション（エントロピー付き）・依存ライブラリ・シンボルを表示 |
| [`embedded_scan.py`](reversing/surface/embedded_scan.py) | バイナリ内に埋め込まれたファイル（ELF/PE/ZIP/PNG/gzip/zlib 等）をシグネチャで検出・切り出し（binwalk 簡易版） |
| [`entropy.py`](reversing/surface/entropy.py) | ファイルをブロックごとにエントロピー計算してグラフ表示（パック・暗号化・圧縮データ領域の発見） |
| [`pe_info.py`](reversing/surface/pe_info.py) | PE (exe/dll) のヘッダ・保護機構・セクション（エントロピー付き）・インポート/エクスポート・TLS・PDB パス・オーバーレイを表示 |
| [`strings_ex.py`](reversing/surface/strings_ex.py) | strings の強化版（ASCII + UTF-16LE/BE/UTF-32、オフセット表示、flag/URL/成功失敗メッセージ/base64 テーブル等の分類） |
| [`triage.sh`](reversing/surface/triage.sh) | リバーシング問題の最初の一手（file・ハッシュ・ELF/PE 情報・言語/パッカー判定・flag/注目文字列・エントロピーを一括表示） |

### 🧩 reversing/static — 静的解析・パッチ（詳細: [reversing/static/README.md](reversing/static/README.md)）

| スクリプト | 用途 |
|---|---|
| [`DecompileAll.java`](reversing/static/DecompileAll.java) | Ghidra ヘッドレス用ポストスクリプト（全関数 or 名前一致の関数を逆コンパイルして 1 つの C ファイルに出力） |
| [`disasm.sh`](reversing/static/disasm.sh) | objdump ラッパー（Intel 記法で関数/アドレス範囲を逆アセンブル、関数一覧、stripped バイナリの main 特定） |
| [`extract_bytes.py`](reversing/static/extract_bytes.py) | ELF/PE の仮想アドレス・シンボル名・ファイルオフセットからデータを抜き出し C 配列/Python リスト/u32 配列等に整形（暗号化テーブルの取り出し用） |
| [`ghidra_decompile.sh`](reversing/static/ghidra_decompile.sh) | Ghidra をヘッドレス実行して全関数（または指定関数）を C 言語に逆コンパイルしファイル出力（GUI 不要） |
| [`patch_bytes.py`](reversing/static/patch_bytes.py) | バイナリパッチ（VA/オフセット指定でバイト書換・NOP 埋め・条件分岐反転・常に jmp・即 return）とバイト列検索 |
| [`pyc_tool.py`](reversing/static/pyc_tool.py) | .pyc の Python バージョン判定・ヘッダ修復（pyinstxtractor 出力向け）・逆アセンブル/定数一覧（同バージョンの Python で実行時） |
| [`r2_analyze.sh`](reversing/static/r2_analyze.sh) | radare2 を非対話で実行して定番の解析結果を出す（情報・関数一覧・main 逆アセ/疑似 C・文字列・文字列の参照元・呼び出し関係） |

### 🐞 reversing/dynamic — 動的解析（詳細: [reversing/dynamic/README.md](reversing/dynamic/README.md)）

| スクリプト | 用途 |
|---|---|
| [`frida_hook.js`](reversing/dynamic/frida_hook.js) | Frida フックスクリプト（strcmp/memcmp 等の引数ログ、ptrace/IsDebuggerPresent 回避、任意アドレスでのレジスタ表示・戻り値書換） |
| [`gdb_cmp_hook.py`](reversing/dynamic/gdb_cmp_hook.py) | gdb 用 Python スクリプト: strcmp/strncmp/memcmp/strstr 等の引数を止めずにログ出力し、ptrace アンチデバッグも自動回避 |
| [`ld_preload_hook.c`](reversing/dynamic/ld_preload_hook.c) | LD_PRELOAD 用フックライブラリ（strcmp/memcmp 等の引数ログ、ptrace アンチデバッグ回避、sleep 無効化、time/rand の固定） |
| [`qemu_run.sh`](reversing/dynamic/qemu_run.sh) | ARM/AArch64/MIPS/RISC-V/PowerPC/x86 など他アーキの Linux ELF を qemu-user で実行（アーキ自動判定・sysroot 自動選択・gdb 接続待ち） |
| [`trace.sh`](reversing/dynamic/trace.sh) | ltrace / strace の定番オプションをモード指定で実行（ライブラリ呼び出し・比較関数・システムコール・ファイル・ネットワーク） |

### 🧮 reversing/solve — シンボリック実行・ソルバ（詳細: [reversing/solve/README.md](reversing/solve/README.md)）

| スクリプト | 用途 |
|---|---|
| [`angr_solve.py`](reversing/solve/angr_solve.py) | angr のシンボリック実行で「成功メッセージに到達する入力」を自動探索（stdin / argv 入力、文字列 or アドレスで find/avoid 指定） |
| [`sidechannel_brute.py`](reversing/solve/sidechannel_brute.py) | 実行命令数のサイドチャネルで flag を 1 文字ずつ総当たり（先頭から比較して不一致で抜ける実装に有効。perf / valgrind） |
| [`z3_template.py`](reversing/solve/z3_template.py) | Z3 で「逆コンパイルした判定ロジック」を制約として書いて flag を解くテンプレート（XOR・加算・ローテート・連立式・全解列挙の例つき） |

### 🛡️ soc — NOC/SOC 運用・ログ解析（詳細: [soc/README.md](soc/README.md)）

| スクリプト | 用途 |
|---|---|
| [`access_log_stats.py`](soc/access_log_stats.py) | Apache/Nginx アクセスログ (combined) の集計と怪しいリクエスト（SQLi/XSS/LFI/スキャナ）検出 |
| [`auth_log_bruteforce.py`](soc/auth_log_bruteforce.py) | auth.log / secure から SSH ログイン失敗・成功を IP 別に集計しブルートフォースを検出 |
| [`defang.py`](soc/defang.py) | IOC の defang / refang 変換（hxxp, [.], [@] など） |
| [`hash_file.py`](soc/hash_file.py) | ファイルの MD5 / SHA1 / SHA256 を一括算出（VirusTotal 照会用 URL 付き） |
| [`ioc_extract.py`](soc/ioc_extract.py) | テキスト/ログから IP・ドメイン・URL・ハッシュ・メールを抽出（defang 済み入力にも対応） |
| [`port_check.py`](soc/port_check.py) | TCP ポート疎通確認（複数 host:port を並列チェック、応答時間表示） |
| [`whois_lookup.sh`](soc/whois_lookup.sh) | IP/ドメインの whois・DNS レコード・逆引きをまとめて取得 |

<!-- SNIPPETS:END -->

---

## 用途別の逆引き

各分野の README にさらに詳しい逆引きがあります。

| やりたいこと | 使うもの |
|---|---|
| 謎の文字列を渡された | `encoding/auto_decode.py` → 外れたら `hexconv.py` で全形式を眺める |
| `synt{...}` のような文字列 | `encoding/rot.py --brute --grep flag` |
| 謎のバイト列と `flag{` の形式だけわかる | `encoding/xor.py --known 'flag{'` で鍵を推定 |
| pcap を渡された（最初の一手） | `network/pcap/pcap_summary.sh` → [pcap/README.md](network/pcap/README.md#よくある出題パターン) |
| HTTP でファイルがやり取りされている | `network/pcap/extract_http.sh` |
| 長いサブドメインの DNS クエリが大量にある | `network/pcap/dns_queries.sh` → `dns_exfil.py` |
| USB の pcap（URB_INTERRUPT が大量） | `network/pcap/usb_keyboard.py` |
| 実行ファイルを渡された（最初の一手） | `reversing/surface/triage.sh` → [reversing/README.md](reversing/README.md#用途別の逆引き) |
| strcmp に渡る正解文字列を見たい | `reversing/dynamic/trace.sh cmp` / `gdb_cmp_hook.py` |
| 判定ロジックを全部 C で読みたい | `reversing/static/ghidra_decompile.sh` |
| 判定を通る入力を自動で探したい | `reversing/solve/angr_solve.py` |
| PyInstaller の exe / .pyc | `reversing/static/pyc_tool.py` |
| ARM / MIPS のバイナリを動かしたい | `reversing/dynamic/qemu_run.sh` |
| レポートから IOC を拾ってチケットに貼る | `soc/ioc_extract.py` → `soc/defang.py` |
| SSH への総当たりがないか確認 | `soc/auth_log_bruteforce.py` |
| Web サーバへの攻撃痕跡を調べる | `soc/access_log_stats.py --suspicious` |
| 怪しいファイルを調べる | `soc/hash_file.py --vt` → `reversing/surface/pe_info.py` |
| ポートが開いているか確認 | `soc/port_check.py host:443` |
| サブネットの範囲・所属を確認 | `network/recon/subnet_calc.py` |

---

## snip コマンド

| コマンド | 説明 |
|---|---|
| `snip list [カテゴリ]` (`ls`) | カテゴリ別一覧。例: `snip list soc`, `snip list reversing/static` |
| `snip search <語...>` (`s`) | 説明・タグ・パスを AND 検索。例: `snip search pcap dns`, `snip search anti-debug` |
| `snip show <名前>` | 説明・タグ・依存・使用例を表示。`--cat` で本文を出力 |
| `snip path <名前>` | 絶対パスを出力。`python3 "$(snip path b64)" ...` のように使う |
| `snip readme` | ルートと各分野の README の「スクリプト一覧」を再生成。`--check` で差分があれば非 0 終了 |

`<名前>` はファイル名（`b64.py`）、拡張子なし（`b64`）、パス（`encoding/b64.py`）のいずれでも指定できます。

---

## スニペットの追加方法

1. **置き場所を決める** — 既存カテゴリに合うものはそこへ。新カテゴリを作る場合は `snip` の `CATEGORY_TITLES` に見出しを追加し、ディレクトリに `README.md` を作る（下記 4.）
2. **ファイル名** — `snake_case`、内容がわかる名前（`<対象>_<動作>.py` など）
3. **先頭にメタデータヘッダを書く**（`snip` と README 一覧が読み取ります。`@desc` がないファイルは無視されます）

   ```python
   #!/usr/bin/env python3
   # @desc:  1 行の説明（README の「用途」列になる）
   # @tags:  ctf, network, pcap      ← snip search の対象
   # @deps:  tshark                  ← 外部依存。なければ none
   # @usage: python3 network/pcap/foo.py capture.pcap
   ```

   対象拡張子は `.py` `.sh` `.c` `.js` `.java`。C / JavaScript / Java は `// @desc:` のように `//` コメントで書きます。

4. **分野の README** — 一覧表を自動生成させたい README には次のマーカーを置き、詳しい使い方を手で追記する

   ```markdown
   <!-- SNIPPETS:START -->
   <!-- SNIPPETS:END -->
   ```

5. **規約**
   - Python: `argparse` で `-h` を出せるようにし、入力はファイル引数か stdin から。処理は関数に分けてコピペ流用しやすく
   - Bash: `set -euo pipefail`、引数不足時は usage を表示、依存コマンドの存在チェックをする
   - 実行権限を付ける: `chmod +x <file>`
6. **README を更新**: `./snip readme`（ディレクトリ構成のツリーと逆引き表は手で追記）

---

## 注意

- `nmap_quick.sh` や `port_check.py` など能動的に通信するスクリプトは、**許可された対象**（CTF の環境や自組織の資産）にのみ使ってください。
- リバースエンジニアリング対象のバイナリ（特に配布元が不明なもの）は、**使い捨ての VM / コンテナ**で実行してください。
