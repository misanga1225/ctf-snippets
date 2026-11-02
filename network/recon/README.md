# 🛰️ network/recon — 偵察・ネットワーク計算

ポートスキャン（nmap プリセット）と CIDR / サブネット計算のスクリプト集です。

← [network/README.md](../README.md) ／ [README.md（トップ）](../../README.md)

> ⚠ 能動的なスキャンは**許可された対象**（CTF の問題サーバ・自組織の資産）にのみ実行してください。

---

## スクリプト一覧

<!-- SNIPPETS:START -->

### 🛰️ network/recon — 偵察・ネットワーク計算

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`nmap_quick.sh`](nmap_quick.sh) | nmap の定番スキャンプリセット（全ポート高速発見 → 開いたポートだけ詳細スキャン） | nmap | `bash network/recon/nmap_quick.sh 10.10.10.5 [full\|quick\|udp\|ping]` |
| [`subnet_calc.py`](subnet_calc.py) | CIDR 計算（ネットワーク/ブロードキャスト/ホスト範囲/包含判定/サブネット分割） | none | `python3 network/recon/subnet_calc.py 192.168.10.37/22 --contains 192.168.11.5 --split 24` |

<!-- SNIPPETS:END -->

---

## スクリプトの詳しい使い方

### nmap_quick.sh

```bash
bash network/recon/nmap_quick.sh 10.10.10.5            # full（既定）: 全 TCP ポートを高速発見 → 開いたポートだけ -sC -sV
bash network/recon/nmap_quick.sh 10.10.10.5 quick      # top 1000 ポートに -sC -sV
bash network/recon/nmap_quick.sh 10.10.10.5 udp        # UDP top 100（sudo が必要）
bash network/recon/nmap_quick.sh 10.10.10.0/24 ping    # ホスト発見のみ
```

結果は `./nmap_<target>_<mode>.{nmap,gnmap,xml}` に保存されます。
`full` は 2 段階（`-p- --min-rate 2000` で開いているポートを探す → そのポートだけ詳細スキャン）なので、全ポート詳細スキャンより大幅に速いです。

### subnet_calc.py

```bash
python3 network/recon/subnet_calc.py 192.168.10.37/22
python3 network/recon/subnet_calc.py 192.168.10.37/22 --contains 192.168.11.5 10.0.0.1   # 含まれるか
python3 network/recon/subnet_calc.py 10.0.0.0/16 --split 24       # /24 に分割して列挙
python3 network/recon/subnet_calc.py 10.0.0.0/29 --list           # ホスト IP を全列挙
python3 network/recon/subnet_calc.py 192.168.0.0/255.255.252.0    # サブネットマスク表記
python3 network/recon/subnet_calc.py 2001:db8::/48                # IPv6
```

ネットワークアドレス・ブロードキャスト・ホスト範囲・ホスト数・ワイルドカードマスクを表示します。

---

## nmap コマンド集

```bash
nmap -sC -sV -p- -T4 -oA scan 10.10.10.5       # 定番: 全ポート + スクリプト + バージョン
nmap -p 22,80,443 -sV 10.10.10.5               # ポート指定
nmap -sU --top-ports 50 10.10.10.5             # UDP（root）
nmap -sn 10.10.10.0/24                         # ping スキャン（ホスト発見）
nmap -Pn 10.10.10.5                            # ping に応答しないホスト
nmap -O 10.10.10.5                             # OS 推定（root）
nmap --script vuln 10.10.10.5                  # 脆弱性スクリプト
nmap --script 'http-*' -p 80 10.10.10.5        # HTTP 系スクリプト
nmap --script-help http-enum                   # スクリプトの説明
ls /usr/share/nmap/scripts | grep smb          # スクリプト一覧
```

| オプション | 意味 |
|---|---|
| `-sS` / `-sT` / `-sU` | SYN（既定・root） / TCP connect / UDP |
| `-sC` / `-sV` | 既定スクリプト / サービスバージョン |
| `-p-` / `--top-ports N` | 全ポート / 上位 N |
| `-T4` / `--min-rate 2000` | 速度 |
| `-n` / `-Pn` | DNS 逆引きしない / ホスト発見を省略 |
| `-oA name` | 全形式で保存（.nmap / .gnmap / .xml） |

## その他のツール

| ツール | 用途 |
|---|---|
| `masscan -p1-65535 --rate 10000 10.10.10.5` | 超高速ポートスキャン |
| `rustscan -a 10.10.10.5 -- -sC -sV` | 高速発見 → nmap に渡す |
| `nc -zv 10.10.10.5 20-100` | netcat で簡易ポートスキャン |
| `curl -I http://host/` | HTTP ヘッダ |
| `gobuster dir -u http://host/ -w wordlist.txt` / `ffuf` | ディレクトリ探索 |
| `ipcalc 192.168.1.0/24` | サブネット計算（`subnet_calc.py` と同等） |
| [`soc/port_check.py`](../../soc/README.md#port_checkpy) | 特定ポートの疎通確認（nmap がない環境） |
| [`soc/whois_lookup.sh`](../../soc/README.md#whois_lookupsh) | IP / ドメインの所有者 |
