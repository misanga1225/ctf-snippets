# 🌐 network — ネットワーク

CTF のネットワーク問題（pcap 解析）と、偵察・ネットワーク計算のスクリプト集です。

← [README.md（トップ）](../README.md)

| ディレクトリ | 内容 | 詳細 |
|---|---|---|
| [`pcap/`](pcap/) | 📦 パケットキャプチャ解析（tshark ラッパー・隠しデータ抽出） | [pcap/README.md](pcap/README.md) |
| [`recon/`](recon/) | 🛰️ 偵察（nmap プリセット）・サブネット計算 | [recon/README.md](recon/README.md) |

## pcap 問題の基本フロー

```
pcap_summary.sh で全体像（どのプロトコルが多いか・誰と誰が話しているか）
   ├─ HTTP が多い        → extract_http.sh（ファイル抽出・POST の中身）
   ├─ FTP/Telnet/認証    → creds_sniff.sh
   ├─ DNS が異常に多い   → dns_queries.sh → dns_exfil.py
   ├─ ICMP が多い        → icmp_data.py
   ├─ USB (URB)          → usb_keyboard.py
   └─ その他 TCP/UDP     → follow_tcp.sh で全ストリームをダンプして grep
```

## スクリプト一覧

<!-- SNIPPETS:START -->

### 📦 network/pcap — パケットキャプチャ解析

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`creds_sniff.sh`](pcap/creds_sniff.sh) | 平文認証情報の抽出（FTP/Telnet/HTTP Basic/HTTP POST/POP/IMAP/SMTP AUTH/NTLM） | tshark | `bash network/pcap/creds_sniff.sh capture.pcap` |
| [`dns_exfil.py`](pcap/dns_exfil.py) | DNS トンネル/サブドメインに埋め込まれたデータを結合・復元（hex/base32/base64 自動試行） | tshark（クエリ名リストを stdin で渡す場合は不要） | `python3 network/pcap/dns_exfil.py capture.pcap --domain evil.com -o out.bin` |
| [`dns_queries.sh`](pcap/dns_queries.sh) | DNS クエリ名・レコード種別・応答を一覧化（ユニーク/出現回数順） | tshark | `bash network/pcap/dns_queries.sh capture.pcap [--answers]` |
| [`extract_http.sh`](pcap/extract_http.sh) | HTTP リクエスト一覧を表示し、転送ファイル（HTTP/SMB/FTP-DATA 等のオブジェクト）を抽出 | tshark | `bash network/pcap/extract_http.sh capture.pcap ./out` |
| [`follow_tcp.sh`](pcap/follow_tcp.sh) | 全 TCP/UDP ストリームを個別ファイルにダンプ（Follow TCP Stream の一括版） | tshark | `bash network/pcap/follow_tcp.sh capture.pcap ./streams [tcp\|udp] [ascii\|raw]` |
| [`icmp_data.py`](pcap/icmp_data.py) | ICMP ペイロードを結合して隠しデータを抽出（1 パケット 1 バイト型・TTL/ID 埋め込み型にも対応） | tshark | `python3 network/pcap/icmp_data.py capture.pcap --type request --offset 0 --length 1` |
| [`pcap_summary.sh`](pcap/pcap_summary.sh) | pcap の全体像を把握（プロトコル階層・IP 会話・TCP 会話・HTTP ホスト・DNS 統計） | tshark | `bash network/pcap/pcap_summary.sh capture.pcap` |
| [`usb_keyboard.py`](pcap/usb_keyboard.py) | USB HID キーボードの打鍵データを pcap から復元（Shift・Backspace 対応） | tshark（hex 行を stdin で渡す場合は不要） | `python3 network/pcap/usb_keyboard.py usb.pcapng` |

### 🛰️ network/recon — 偵察・ネットワーク計算

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`nmap_quick.sh`](recon/nmap_quick.sh) | nmap の定番スキャンプリセット（全ポート高速発見 → 開いたポートだけ詳細スキャン） | nmap | `bash network/recon/nmap_quick.sh 10.10.10.5 [full\|quick\|udp\|ping]` |
| [`subnet_calc.py`](recon/subnet_calc.py) | CIDR 計算（ネットワーク/ブロードキャスト/ホスト範囲/包含判定/サブネット分割） | none | `python3 network/recon/subnet_calc.py 192.168.10.37/22 --contains 192.168.11.5 --split 24` |

<!-- SNIPPETS:END -->
