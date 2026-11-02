# 📦 network/pcap — パケットキャプチャ解析

pcap / pcapng から通信の全体像を把握し、転送ファイル・認証情報・DNS/ICMP に隠されたデータ・USB キーボードの打鍵を取り出すスクリプト集です。
ほとんどが **tshark**（Wireshark の CLI）のラッパーです。

← [network/README.md](../README.md) ／ [README.md（トップ）](../../README.md)

```bash
brew install wireshark        # macOS（tshark も入る）
sudo apt install tshark       # Debian / Ubuntu / Kali
```

---

## 目次

- [スクリプト一覧](#スクリプト一覧)
- [スクリプトの詳しい使い方](#スクリプトの詳しい使い方)
- [tshark コマンド集](#tshark-コマンド集)
- [Wireshark 表示フィルタ早見表](#wireshark-表示フィルタ早見表)
- [その他のツール](#その他のツール)
- [よくある出題パターン](#よくある出題パターン)

---

## スクリプト一覧

<!-- SNIPPETS:START -->

### 📦 network/pcap — パケットキャプチャ解析

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`creds_sniff.sh`](creds_sniff.sh) | 平文認証情報の抽出（FTP/Telnet/HTTP Basic/HTTP POST/POP/IMAP/SMTP AUTH/NTLM） | tshark | `bash network/pcap/creds_sniff.sh capture.pcap` |
| [`dns_exfil.py`](dns_exfil.py) | DNS トンネル/サブドメインに埋め込まれたデータを結合・復元（hex/base32/base64 自動試行） | tshark（クエリ名リストを stdin で渡す場合は不要） | `python3 network/pcap/dns_exfil.py capture.pcap --domain evil.com -o out.bin` |
| [`dns_queries.sh`](dns_queries.sh) | DNS クエリ名・レコード種別・応答を一覧化（ユニーク/出現回数順） | tshark | `bash network/pcap/dns_queries.sh capture.pcap [--answers]` |
| [`extract_http.sh`](extract_http.sh) | HTTP リクエスト一覧を表示し、転送ファイル（HTTP/SMB/FTP-DATA 等のオブジェクト）を抽出 | tshark | `bash network/pcap/extract_http.sh capture.pcap ./out` |
| [`follow_tcp.sh`](follow_tcp.sh) | 全 TCP/UDP ストリームを個別ファイルにダンプ（Follow TCP Stream の一括版） | tshark | `bash network/pcap/follow_tcp.sh capture.pcap ./streams [tcp\|udp] [ascii\|raw]` |
| [`icmp_data.py`](icmp_data.py) | ICMP ペイロードを結合して隠しデータを抽出（1 パケット 1 バイト型・TTL/ID 埋め込み型にも対応） | tshark | `python3 network/pcap/icmp_data.py capture.pcap --type request --offset 0 --length 1` |
| [`pcap_summary.sh`](pcap_summary.sh) | pcap の全体像を把握（プロトコル階層・IP 会話・TCP 会話・HTTP ホスト・DNS 統計） | tshark | `bash network/pcap/pcap_summary.sh capture.pcap` |
| [`usb_keyboard.py`](usb_keyboard.py) | USB HID キーボードの打鍵データを pcap から復元（Shift・Backspace 対応） | tshark（hex 行を stdin で渡す場合は不要） | `python3 network/pcap/usb_keyboard.py usb.pcapng` |

<!-- SNIPPETS:END -->

---

## スクリプトの詳しい使い方

### pcap_summary.sh — 最初の一手

```bash
bash network/pcap/pcap_summary.sh capture.pcap
```

capinfos（期間・パケット数）→ プロトコル階層 → IP 会話 → TCP 会話 → HTTP のホスト/リクエスト → DNS クエリ上位 → pcap を直接 grep した flag っぽい文字列、を順に表示します。
**プロトコル階層で割合が大きいもの・普段見ないプロトコル**が出題の中心です。

### extract_http.sh — HTTP のリクエストと転送ファイル

```bash
bash network/pcap/extract_http.sh capture.pcap            # ./out/ に出力
bash network/pcap/extract_http.sh capture.pcap ./files
```

HTTP リクエスト一覧（フレーム番号・送信元・メソッド・ホスト・URI・UA）、POST の本文を表示し、HTTP / SMB / TFTP / IMF（メール）/ FTP-DATA で転送されたファイルを `out/<proto>/` に書き出して `file` で種類を表示します。

### follow_tcp.sh — 全ストリームのダンプ

```bash
bash network/pcap/follow_tcp.sh capture.pcap                    # ./streams/tcp_stream_N.txt（ASCII）
bash network/pcap/follow_tcp.sh capture.pcap ./st udp           # UDP
bash network/pcap/follow_tcp.sh capture.pcap ./st tcp raw       # hex（バイナリを復元したい時）
grep -ail 'flag{' streams/*                                     # flag を含むストリームを探す
```

raw で出したストリームは `xxd -r -p` でバイナリに戻せます（Wireshark の Follow TCP Stream の一括版）。

### creds_sniff.sh — 平文の認証情報

```bash
bash network/pcap/creds_sniff.sh capture.pcap
```

tshark の credentials タップ、FTP USER/PASS、HTTP Basic 認証、HTTP POST（pass/login/user を含むもの）、POP/IMAP/SMTP AUTH、Telnet（1 文字ずつ送られるデータを結合）、NTLM（hashcat `-m 5600` の材料）を表示します。

### dns_queries.sh / dns_exfil.py — DNS トンネル

```bash
bash network/pcap/dns_queries.sh capture.pcap              # クエリ名を出現回数順に
bash network/pcap/dns_queries.sh capture.pcap --answers    # 応答（A / AAAA / CNAME / TXT）も
python3 network/pcap/dns_exfil.py capture.pcap --domain evil.com             # サブドメインを結合してデコード
python3 network/pcap/dns_exfil.py capture.pcap -d evil.com -o out.bin        # 結果を保存
python3 network/pcap/dns_exfil.py capture.pcap -d evil.com --codec base32    # デコード方式を固定
tshark -r c.pcap -Y dns -T fields -e dns.qry.name | python3 network/pcap/dns_exfil.py -d evil.com   # stdin
```

`dns_exfil.py` は `<data>.<data>.evil.com` の `<data>` 部分を順に連結し、hex / base32 / base64 / base64url で復号を試して印字可能な結果を表示します。再送による連続重複は除去します（`--keep-dups` で無効化）。

### icmp_data.py — ICMP に隠されたデータ

```bash
python3 network/pcap/icmp_data.py capture.pcap                         # Echo Request のペイロードを結合
python3 network/pcap/icmp_data.py capture.pcap --type reply            # Echo Reply
python3 network/pcap/icmp_data.py capture.pcap --offset 0 --length 1   # 各パケット 1 バイトずつ
python3 network/pcap/icmp_data.py capture.pcap --field ip.ttl          # TTL に埋め込まれている
python3 network/pcap/icmp_data.py capture.pcap --field ip.id           # IP ID に埋め込まれている
python3 network/pcap/icmp_data.py capture.pcap --src 10.0.0.5 -o out.bin
```

### usb_keyboard.py — USB キーボードの打鍵

```bash
python3 network/pcap/usb_keyboard.py usb.pcapng           # Shift / Backspace を反映した文字列
python3 network/pcap/usb_keyboard.py usb.pcapng --raw     # <BS> などを残す
```

`usb.capdata` / `usbhid.data` の 8 バイト HID レポートを解釈します。マウス（4 バイト程度のレポート）は対象外です。

---

## tshark コマンド集

```bash
tshark -r c.pcap                                     # 一覧（Wireshark の上段）
tshark -r c.pcap -Y 'http.request'                   # 表示フィルタ
tshark -r c.pcap -Y 'tcp.stream eq 3' -V             # 詳細（中段）
tshark -r c.pcap -Y 'frame.number==10' -x            # hex ダンプ（下段）
tshark -r c.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport -Y tcp.flags.syn==1
tshark -r c.pcap -T fields -E separator=, -E header=y -e frame.time -e ip.src ...   # CSV
tshark -r c.pcap -q -z io,phs                        # プロトコル階層
tshark -r c.pcap -q -z conv,tcp                      # TCP 会話
tshark -r c.pcap -q -z endpoints,ip                  # 端点
tshark -r c.pcap -q -z http,tree                     # HTTP 統計
tshark -r c.pcap -q -z follow,tcp,ascii,3            # ストリーム 3 を表示
tshark -r c.pcap -q -z follow,tcp,raw,3              # hex で
tshark -r c.pcap --export-objects http,./out         # HTTP で転送されたファイル
tshark -r c.pcap -o tls.keylog_file:keys.log -Y http # TLS を SSLKEYLOGFILE で復号
tshark -r c.pcap -o 'uat:user_dlts:"User 0 (DLT=147)","eth","0","","0",""'   # 独自 DLT
editcap -F pcap in.pcapng out.pcap                   # pcapng → pcap
mergecap -w out.pcap a.pcap b.pcap                   # 結合
capinfos c.pcap                                      # 概要
```

> tshark 4.x ではバイト列フィールド（`http.file_data` など）が hex で出力されます。`xxd -r -p` で戻してください。

---

## Wireshark 表示フィルタ早見表

| フィルタ | 意味 |
|---|---|
| `ip.addr == 10.0.0.5` / `ip.src ==` / `ip.dst ==` | IP |
| `tcp.port == 4444` / `udp.port == 53` | ポート |
| `tcp.stream eq 3` | TCP ストリーム |
| `http.request.method == "POST"` | POST |
| `http.request.uri contains "flag"` | URI に文字列 |
| `frame contains "flag"` / `frame matches "(?i)flag\\{"` | パケット全体を検索（正規表現） |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN（スキャン検出） |
| `dns.qry.name contains "evil"` | DNS クエリ |
| `icmp.type == 8` | ping 要求 |
| `ftp-data` / `smb2` / `tftp` / `smtp` / `telnet` | プロトコル |
| `usb.transfer_type == 0x01` | USB の interrupt 転送 |
| `!(arp or dns or icmp)` | ノイズ除去 |
| `tls.handshake.extensions_server_name` | TLS の SNI（通信先ホスト名） |

---

## その他のツール

| ツール | 用途 |
|---|---|
| Wireshark（GUI） | Statistics → Conversations / Protocol Hierarchy、File → Export Objects、Follow Stream |
| NetworkMiner | ファイル・画像・認証情報を自動抽出（GUI） |
| tcpflow | ストリームをファイルに分割: `tcpflow -r c.pcap -o out/` |
| scapy | Python でパケットを自由に処理: `rdpcap('c.pcap')` |
| zeek | ログ（conn.log / http.log / dns.log）に変換して集計 |
| `strings -n 8 c.pcap \| grep -i flag` | とりあえず平文検索 |
| `binwalk -e c.pcap` / `foremost` | pcap に埋もれたファイルを強引に抽出 |

---

## よくある出題パターン

| パターン | 手順 |
|---|---|
| HTTP でファイル（zip / 画像）をダウンロード | `extract_http.sh` → 取り出したファイルを解析 |
| FTP でファイル転送 | `extract_http.sh`（ftp-data）/ `follow_tcp.sh` の raw → `xxd -r -p` |
| Telnet / FTP のパスワード | `creds_sniff.sh` |
| TLS 通信 + 鍵ログファイルが配布 | `tshark -o tls.keylog_file:keys.log` で復号 |
| TLS + RSA 秘密鍵が配布（古い TLS） | Wireshark の RSA keys list に登録 |
| DNS のサブドメインが長い / 大量 | `dns_queries.sh` → `dns_exfil.py` |
| ping のサイズや TTL が不揃い | `icmp_data.py --length 1` / `--field ip.ttl` |
| USB キーボード | `usb_keyboard.py` |
| USB マウス | 座標を積算してプロット（matplotlib） |
| 802.11（無線） | `aircrack-ng -w rockyou.txt c.pcap` で WPA の PSK → `airdecap-ng` で復号 |
| 独自プロトコル（TCP） | `follow_tcp.sh raw` → Python で構造を解析 |
| ポートスキャンの痕跡 | `tcp.flags.syn==1 && tcp.flags.ack==0` を送信元で集計 |
