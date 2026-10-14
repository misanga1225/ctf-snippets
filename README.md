# ctf-snippets

CTF（ネットワーク系）と NOC/SOC 業務で使うスクリプトをまとめたスニペット集。

- **言語**: Python 3（メイン）+ Bash（tshark / nmap などのラッパー）
- **依存**: 基本は Python 標準ライブラリのみ。外部コマンドが必要なものは各スクリプトの `@deps` と下表に記載
- **使い方**: 各スクリプトは単体で実行でき、入力をパイプでつなげられます
- **検索**: 付属の `snip` コマンドで一覧・キーワード検索・使い方表示ができます

---

## 目次

- [セットアップ](#セットアップ)
- [クイックスタート](#クイックスタート)
- [ディレクトリ構成](#ディレクトリ構成)
- [スクリプト一覧](#スクリプト一覧)
- [用途別の逆引き](#用途別の逆引き)
- [snip コマンド](#snip-コマンド)
- [スニペットの追加方法](#スニペットの追加方法)

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

# 任意（テスト用 pcap の生成などに）
pip install -r requirements.txt
```

動作要件: Python 3.8 以上、Bash。pcap 系は tshark 4.x で動作確認済みです。

---

## クイックスタート

```bash
# 何があるか探す
snip list                 # 全スクリプト一覧
snip search base64        # キーワード検索（複数語は AND）
snip show xor             # 使い方・依存を表示
snip show xor --cat       # 本文を出力（別環境へコピペしたいとき）

# 実行する
python3 encoding/b64.py -d 'ZmxhZ3t4fQ=='
echo 'synt{ebg13}' | python3 encoding/rot.py

# パイプでつなぐ: base64 → XOR(0x42) の順で復号
echo 'JC4jJTk6Pw==' | encoding/b64.py -d | encoding/xor.py -k 0x42

# 何重にエンコードされているかわからないときは自動判定
encoding/auto_decode.py 'NjY2YzYxNjc3Yjc4N2Q='
# => [base64 -> hex] flag{x}

# どこからでもスクリプトのパスを取得
python3 "$(snip path dns_exfil)" capture.pcap -d evil.com
```

---

## ディレクトリ構成

```
ctf-snippets/
├── README.md
├── snip                        スクリプトの一覧・検索・表示 CLI
├── requirements.txt            任意依存（scapy）
│
├── encoding/                   🔤 エンコード / デコード
│   ├── auto_decode.py            多段エンコードの自動判定（CyberChef Magic 簡易版）
│   ├── b64.py                    base64 / 32 / 85 / 58
│   ├── hexconv.py                hex ⇔ 文字列 ⇔ 整数 ⇔ 2進数
│   ├── rot.py                    ROT13 / ROT47 / Caesar 総当たり
│   ├── urlenc.py                 URL エンコード（多重デコード対応）
│   └── xor.py                    XOR・単一バイト総当たり・既知平文から鍵推定
│
├── network/
│   ├── pcap/                   📦 パケットキャプチャ解析（tshark 利用）
│   │   ├── pcap_summary.sh       まず最初に実行: 全体像の把握
│   │   ├── extract_http.sh       HTTP リクエスト一覧＋転送ファイル抽出
│   │   ├── follow_tcp.sh         全ストリームをファイルにダンプ
│   │   ├── creds_sniff.sh        平文の認証情報を抽出
│   │   ├── dns_queries.sh        DNS クエリ一覧
│   │   ├── dns_exfil.py          DNS トンネルからのデータ復元
│   │   ├── icmp_data.py          ICMP に隠されたデータの抽出
│   │   └── usb_keyboard.py       USB キーボード打鍵の復元
│   └── recon/                  🛰️ 偵察・ネットワーク計算
│       ├── nmap_quick.sh         nmap 定番プリセット
│       └── subnet_calc.py        CIDR / サブネット計算
│
└── soc/                        🛡️ NOC/SOC 運用・ログ解析
    ├── access_log_stats.py       Web アクセスログ集計・攻撃検出
    ├── auth_log_bruteforce.py    SSH ブルートフォース検出
    ├── defang.py                 IOC の defang / refang
    ├── hash_file.py              ファイルハッシュ（VirusTotal 照会用）
    ├── ioc_extract.py            テキストから IOC を抽出
    ├── port_check.py             TCP 疎通確認
    └── whois_lookup.sh           whois / DNS まとめ引き
```

---

## スクリプト一覧

> この節は `./snip readme` で各スクリプトのヘッダから自動生成されます。手で編集しないでください。

<!-- SNIPPETS:START -->

### 🔤 encoding — エンコード / デコード

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`auto_decode.py`](encoding/auto_decode.py) | 多段エンコードを自動判定してデコード（CyberChef Magic 簡易版、flag 形式を検出） | none | `python3 encoding/auto_decode.py 'NjY2YzYxNjc3Yjc4N2Q='` |
| [`b64.py`](encoding/b64.py) | base64 / base32 / base85 / ascii85 / base58 のエンコード・デコード | none | `echo 'ZmxhZ3t4fQ==' \| python3 encoding/b64.py -d` |
| [`hexconv.py`](encoding/hexconv.py) | hex / bytes / 整数 / 2進数 / 10進バイト列の相互変換 | none | `python3 encoding/hexconv.py -f hex -t str 666c61677b787d` |
| [`rot.py`](encoding/rot.py) | ROT13 / ROT-N / ROT47 / Caesar 全シフト総当たり | none | `python3 encoding/rot.py --brute 'synt{ebg13}'` |
| [`urlenc.py`](encoding/urlenc.py) | URL エンコード / デコード（多重エンコードの完全デコード対応） | none | `python3 encoding/urlenc.py -d --full '%2566lag%257B%2578%257D'` |
| [`xor.py`](encoding/xor.py) | XOR（単一/複数バイト鍵）、単一バイト鍵の総当たり、既知平文からの鍵推定 | none | `python3 encoding/xor.py -k 0x42 -i hex 242e2325393a3f` |

### 📦 network/pcap — パケットキャプチャ解析

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`creds_sniff.sh`](network/pcap/creds_sniff.sh) | 平文認証情報の抽出（FTP/Telnet/HTTP Basic/HTTP POST/POP/IMAP/SMTP AUTH/NTLM） | tshark | `bash network/pcap/creds_sniff.sh capture.pcap` |
| [`dns_exfil.py`](network/pcap/dns_exfil.py) | DNS トンネル/サブドメインに埋め込まれたデータを結合・復元（hex/base32/base64 自動試行） | tshark（クエリ名リストを stdin で渡す場合は不要） | `python3 network/pcap/dns_exfil.py capture.pcap --domain evil.com -o out.bin` |
| [`dns_queries.sh`](network/pcap/dns_queries.sh) | DNS クエリ名・レコード種別・応答を一覧化（ユニーク/出現回数順） | tshark | `bash network/pcap/dns_queries.sh capture.pcap [--answers]` |
| [`extract_http.sh`](network/pcap/extract_http.sh) | HTTP リクエスト一覧を表示し、転送ファイル（HTTP/SMB/FTP-DATA 等のオブジェクト）を抽出 | tshark | `bash network/pcap/extract_http.sh capture.pcap ./out` |
| [`follow_tcp.sh`](network/pcap/follow_tcp.sh) | 全 TCP/UDP ストリームを個別ファイルにダンプ（Follow TCP Stream の一括版） | tshark | `bash network/pcap/follow_tcp.sh capture.pcap ./streams [tcp\|udp] [ascii\|raw]` |
| [`icmp_data.py`](network/pcap/icmp_data.py) | ICMP ペイロードを結合して隠しデータを抽出（1 パケット 1 バイト型・TTL/ID 埋め込み型にも対応） | tshark | `python3 network/pcap/icmp_data.py capture.pcap --type request --offset 0 --length 1` |
| [`pcap_summary.sh`](network/pcap/pcap_summary.sh) | pcap の全体像を把握（プロトコル階層・IP 会話・TCP 会話・HTTP ホスト・DNS 統計） | tshark | `bash network/pcap/pcap_summary.sh capture.pcap` |
| [`usb_keyboard.py`](network/pcap/usb_keyboard.py) | USB HID キーボードの打鍵データを pcap から復元（Shift・Backspace 対応） | tshark（hex 行を stdin で渡す場合は不要） | `python3 network/pcap/usb_keyboard.py usb.pcapng` |

### 🛰️ network/recon — 偵察・ネットワーク計算

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`nmap_quick.sh`](network/recon/nmap_quick.sh) | nmap の定番スキャンプリセット（全ポート高速発見 → 開いたポートだけ詳細スキャン） | nmap | `bash network/recon/nmap_quick.sh 10.10.10.5 [full\|quick\|udp\|ping]` |
| [`subnet_calc.py`](network/recon/subnet_calc.py) | CIDR 計算（ネットワーク/ブロードキャスト/ホスト範囲/包含判定/サブネット分割） | none | `python3 network/recon/subnet_calc.py 192.168.10.37/22 --contains 192.168.11.5 --split 24` |

### 🛡️ soc — NOC/SOC 運用・ログ解析

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`access_log_stats.py`](soc/access_log_stats.py) | Apache/Nginx アクセスログ (combined) の集計と怪しいリクエスト（SQLi/XSS/LFI/スキャナ）検出 | none | `python3 soc/access_log_stats.py access.log --suspicious` |
| [`auth_log_bruteforce.py`](soc/auth_log_bruteforce.py) | auth.log / secure から SSH ログイン失敗・成功を IP 別に集計しブルートフォースを検出 | none | `python3 soc/auth_log_bruteforce.py /var/log/auth.log -t 10` |
| [`defang.py`](soc/defang.py) | IOC の defang / refang 変換（hxxp, [.], [@] など） | none | `echo 'http://evil.com/a' \| python3 soc/defang.py` |
| [`hash_file.py`](soc/hash_file.py) | ファイルの MD5 / SHA1 / SHA256 を一括算出（VirusTotal 照会用 URL 付き） | none | `python3 soc/hash_file.py suspicious.exe --vt` |
| [`ioc_extract.py`](soc/ioc_extract.py) | テキスト/ログから IP・ドメイン・URL・ハッシュ・メールを抽出（defang 済み入力にも対応） | none | `python3 soc/ioc_extract.py report.txt --json` |
| [`port_check.py`](soc/port_check.py) | TCP ポート疎通確認（複数 host:port を並列チェック、応答時間表示） | none | `python3 soc/port_check.py example.com:443 10.0.0.1:22,80,3389 -t 2` |
| [`whois_lookup.sh`](soc/whois_lookup.sh) | IP/ドメインの whois・DNS レコード・逆引きをまとめて取得 | whois, dig | `bash soc/whois_lookup.sh example.com 8.8.8.8` |

<!-- SNIPPETS:END -->

---

## 用途別の逆引き

| やりたいこと | 使うもの |
|---|---|
| 謎の文字列を渡された | `encoding/auto_decode.py` → 外れたら `hexconv.py` で全形式を眺める |
| `synt{...}` のような文字列 | `encoding/rot.py --brute --grep flag` |
| 謎のバイト列と `flag{` の形式だけわかる | `encoding/xor.py --known 'flag{'` で鍵を推定 |
| pcap を渡された（最初の一手） | `network/pcap/pcap_summary.sh` → プロトコル構成を見て下へ |
| HTTP でファイルがやり取りされている | `network/pcap/extract_http.sh` |
| FTP / Telnet / Basic 認証が見える | `network/pcap/creds_sniff.sh` |
| 長いサブドメインの DNS クエリが大量にある | `network/pcap/dns_queries.sh` → `dns_exfil.py` |
| ping が妙に多い / サイズが不揃い | `network/pcap/icmp_data.py`（`--length 1` や `--field ip.ttl` も試す） |
| USB の pcap（URB_INTERRUPT が大量） | `network/pcap/usb_keyboard.py` |
| 特定のストリームの中身をじっくり見たい | `network/pcap/follow_tcp.sh` → `grep -ail flag{` |
| レポートから IOC を拾ってチケットに貼る | `soc/ioc_extract.py` → `soc/defang.py` |
| SSH への総当たりがないか確認 | `soc/auth_log_bruteforce.py` |
| Web サーバへの攻撃痕跡を調べる | `soc/access_log_stats.py --suspicious` |
| 怪しいファイルのハッシュを VT で調べる | `soc/hash_file.py --vt` |
| ポートが開いているか / FW を通るか確認 | `soc/port_check.py host:443` |
| IP やドメインの持ち主を調べる | `soc/whois_lookup.sh` |
| サブネットの範囲・所属を確認 | `network/recon/subnet_calc.py` |

---

## snip コマンド

| コマンド | 説明 |
|---|---|
| `snip list [カテゴリ]` (`ls`) | カテゴリ別一覧。例: `snip list soc`, `snip list network/pcap` |
| `snip search <語...>` (`s`) | 説明・タグ・パスを AND 検索。例: `snip search pcap dns` |
| `snip show <名前>` | 説明・タグ・依存・使用例を表示。`--cat` で本文を出力 |
| `snip path <名前>` | 絶対パスを出力。`python3 "$(snip path b64)" ...` のように使う |
| `snip readme` | README の「スクリプト一覧」を再生成。`--check` で差分があれば非 0 終了 |

`<名前>` はファイル名（`b64.py`）、拡張子なし（`b64`）、パス（`encoding/b64.py`）のいずれでも指定できます。

---

## スニペットの追加方法

1. **置き場所を決める** — 既存カテゴリに合うものはそこへ。新カテゴリを作る場合は `snip` の `CATEGORY_TITLES` に見出しを追加
2. **ファイル名** — `snake_case`、内容がわかる名前（`<対象>_<動作>.py` など）
3. **先頭にメタデータヘッダを書く**（`snip` と README 一覧が読み取ります。`@desc` がないファイルは無視されます）

   ```python
   #!/usr/bin/env python3
   # @desc:  1 行の説明（README の「用途」列になる）
   # @tags:  ctf, network, pcap      ← snip search の対象
   # @deps:  tshark                  ← 外部依存。なければ none
   # @usage: python3 network/pcap/foo.py capture.pcap
   ```

4. **規約**
   - Python: `argparse` で `-h` を出せるようにし、入力はファイル引数か stdin から。処理は関数に分けてコピペ流用しやすく
   - Bash: `set -euo pipefail`、引数不足時は usage を表示、依存コマンドの存在チェックをする
   - 実行権限を付ける: `chmod +x <file>`
5. **README を更新**: `./snip readme`（ディレクトリ構成のツリーと逆引き表は手で追記）

---

## 注意

`nmap_quick.sh` や `port_check.py` など能動的に通信するスクリプトは、**許可された対象**（CTF の環境や自組織の資産）にのみ使ってください。
