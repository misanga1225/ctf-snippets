# 🛡️ soc — NOC/SOC 運用・ログ解析

NOC/SOC 業務やフォレンジック系 CTF で使う、ログ集計・IOC 処理・疎通確認のスクリプト集です。
すべて Python 標準ライブラリ（`whois_lookup.sh` のみ whois / dig）で動きます。ログは `.gz` のまま読めます。

← [README.md（トップ）](../README.md)

> 実データのログには個人情報・IP アドレスが含まれます。リポジトリにコミットしないでください（`.gitignore` で `*.log` などを除外済み）。

---

## 目次

- [スクリプト一覧](#スクリプト一覧)
- [スクリプトの詳しい使い方](#スクリプトの詳しい使い方)
  - [access_log_stats.py](#access_log_statspy) / [auth_log_bruteforce.py](#auth_log_bruteforcepy) / [ioc_extract.py](#ioc_extractpy) / [defang.py](#defangpy) / [hash_file.py](#hash_filepy) / [port_check.py](#port_checkpy) / [whois_lookup.sh](#whois_lookupsh)
- [よくある作業の流れ](#よくある作業の流れ)
- [ログ解析のコマンド集](#ログ解析のコマンド集)
- [Windows イベントログ](#windows-イベントログ)

---

## スクリプト一覧

<!-- SNIPPETS:START -->

### 🛡️ soc — NOC/SOC 運用・ログ解析

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`access_log_stats.py`](access_log_stats.py) | Apache/Nginx アクセスログ (combined) の集計と怪しいリクエスト（SQLi/XSS/LFI/スキャナ）検出 | none | `python3 soc/access_log_stats.py access.log --suspicious` |
| [`auth_log_bruteforce.py`](auth_log_bruteforce.py) | auth.log / secure から SSH ログイン失敗・成功を IP 別に集計しブルートフォースを検出 | none | `python3 soc/auth_log_bruteforce.py /var/log/auth.log -t 10` |
| [`defang.py`](defang.py) | IOC の defang / refang 変換（hxxp, [.], [@] など） | none | `echo 'http://evil.com/a' \| python3 soc/defang.py` |
| [`hash_file.py`](hash_file.py) | ファイルの MD5 / SHA1 / SHA256 を一括算出（VirusTotal 照会用 URL 付き） | none | `python3 soc/hash_file.py suspicious.exe --vt` |
| [`ioc_extract.py`](ioc_extract.py) | テキスト/ログから IP・ドメイン・URL・ハッシュ・メールを抽出（defang 済み入力にも対応） | none | `python3 soc/ioc_extract.py report.txt --json` |
| [`port_check.py`](port_check.py) | TCP ポート疎通確認（複数 host:port を並列チェック、応答時間表示） | none | `python3 soc/port_check.py example.com:443 10.0.0.1:22,80,3389 -t 2` |
| [`whois_lookup.sh`](whois_lookup.sh) | IP/ドメインの whois・DNS レコード・逆引きをまとめて取得 | whois, dig | `bash soc/whois_lookup.sh example.com 8.8.8.8` |

<!-- SNIPPETS:END -->

---

## スクリプトの詳しい使い方

### access_log_stats.py

Apache / Nginx の combined 形式のアクセスログを集計し、攻撃っぽいリクエストを検出します。

```bash
python3 soc/access_log_stats.py access.log                   # 集計（IP・ステータス・メソッド・パス・UA の上位）
python3 soc/access_log_stats.py access.log* --suspicious     # 怪しいリクエストを 1 行ずつ表示
python3 soc/access_log_stats.py access.log --ip 203.0.113.5  # 特定 IP だけ
python3 soc/access_log_stats.py access.log.gz -n 20          # 上位 20 件
zcat access.log.*.gz | python3 soc/access_log_stats.py       # stdin
```

| 検出カテゴリ | パターンの例 |
|---|---|
| `sqli` | `union select`, `or 1=1`, `sleep(`, `information_schema` |
| `xss` | `<script`, `javascript:`, `onerror=` |
| `lfi/traversal` | `../`, `/etc/passwd`, `php://`, `%00` |
| `rce` | `;id`, `$(`, `` ` ``, `cmd.exe`, `/bin/sh` |
| `scanner` | User-Agent に nikto / sqlmap / nmap / gobuster / ffuf / wpscan |
| `sensitive` | `/.git`, `/.env`, `wp-admin`, `phpmyadmin`, `.bak`, `.sql` |

URL デコードしてから判定するので、`%27%20or%201%3D1` のようなエンコード済みの攻撃も拾います。

### auth_log_bruteforce.py

`/var/log/auth.log`（Debian 系）や `/var/log/secure`（RHEL 系）から SSH のログイン失敗・成功を IP 別に集計します。

```bash
python3 soc/auth_log_bruteforce.py /var/log/auth.log             # 5 回以上失敗した IP
python3 soc/auth_log_bruteforce.py /var/log/auth.log* -t 20      # しきい値 20
journalctl -u ssh --no-pager | python3 soc/auth_log_bruteforce.py
```

**失敗が多い IP からの成功（Accepted）**があれば侵入成功の可能性が高く、最優先で確認します。

### ioc_extract.py

レポート・メール・ログから IOC（IP / ドメイン / URL / ハッシュ / メール / CVE）を抽出します。`hxxp://evil[.]com` のような defang 済みの表記も元に戻してから抽出します。

```bash
python3 soc/ioc_extract.py report.txt                  # 種類ごとに表示
python3 soc/ioc_extract.py report.txt --json           # JSON
python3 soc/ioc_extract.py report.txt -t ipv4 -t sha256    # 種類を限定
python3 soc/ioc_extract.py report.txt --private        # プライベート IP も含める
pbpaste | python3 soc/ioc_extract.py                   # クリップボードから（macOS）
```

### defang.py

IOC を安全に共有できる表記（defang）にする / 元に戻す（refang）。

```bash
echo 'http://evil.com/a user@evil.com 1.2.3.4' | python3 soc/defang.py
# hxxp[://]evil[.]com/a user[@]evil[.]com 1[.]2[.]3[.]4
python3 soc/defang.py -r defanged.txt          # 元に戻す
python3 soc/ioc_extract.py report.txt | python3 soc/defang.py   # 抽出してそのままチケットに貼る
```

### hash_file.py

ファイルの MD5 / SHA1 / SHA256 を一括計算します。

```bash
python3 soc/hash_file.py suspicious.exe --vt       # VirusTotal の検索 URL 付き
python3 soc/hash_file.py ./samples/                # ディレクトリは再帰
python3 soc/hash_file.py ./samples/ --csv > hashes.csv
```

> 検体そのものを VirusTotal にアップロードすると第三者に共有されます。まずはハッシュで検索してください。

### port_check.py

TCP ポートの疎通確認を並列で行います（nmap がない環境・FW 変更後の確認向け）。

```bash
python3 soc/port_check.py example.com:443 10.0.0.1:22,80,3389
python3 soc/port_check.py 10.0.0.1:8000-8010 -t 1      # 範囲・タイムアウト 1 秒
python3 soc/port_check.py 10.0.0.1:1-1024 --open       # OPEN だけ表示
```

### whois_lookup.sh

IP / ドメインの whois（要約）・DNS レコード・逆引きをまとめて取得します。`example[.]com` のような defang 表記もそのまま渡せます。

```bash
bash soc/whois_lookup.sh example.com 8.8.8.8
```

ドメイン: A / AAAA / CNAME / MX / NS / TXT と whois（レジストラ・作成日・期限・ネームサーバ）。
IP: PTR（逆引き）と whois（組織名・国・CIDR・AS・abuse 連絡先）。

---

## よくある作業の流れ

```bash
# 脅威レポートの IOC をチケットに貼る
python3 soc/ioc_extract.py report.txt | python3 soc/defang.py

# 怪しい IP を調べる
bash soc/whois_lookup.sh 203.0.113.5
python3 soc/access_log_stats.py access.log --ip 203.0.113.5 --suspicious

# 怪しいファイルを調べる
python3 soc/hash_file.py sample.exe --vt
python3 reversing/surface/pe_info.py sample.exe          # 中身の表層解析（→ reversing/）
python3 reversing/surface/strings_ex.py sample.exe -i | python3 soc/ioc_extract.py
```

---

## ログ解析のコマンド集

```bash
# アクセスログ: IP ごとのリクエスト数
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
# ステータスコード別
awk '{print $9}' access.log | sort | uniq -c | sort -rn
# 特定時間帯（10:00〜10:59）
grep '02/Nov/2026:10:' access.log
# 404 を大量に出している IP（ディレクトリ探索）
awk '$9==404 {print $1}' access.log | sort | uniq -c | sort -rn | head
# 圧縮ログもまとめて
zgrep -h 'Failed password' /var/log/auth.log* | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn

# systemd の journal
journalctl -u ssh --since '2026-11-01' --until '2026-11-02'
journalctl -p err -b                 # 今回の起動以降のエラー
# ログイン履歴
last -a | head ; lastb | head        # 成功 / 失敗（lastb は root）
# 実行中の通信・プロセス
ss -tunap ; lsof -i -P -n
```

---

## Windows イベントログ

| イベント ID | 意味 |
|---|---|
| 4624 / 4625 | ログオン成功 / 失敗（Logon Type 3 = ネットワーク、10 = RDP） |
| 4648 | 明示的な資格情報でのログオン（runas / 横展開） |
| 4672 | 特権の割り当て（管理者ログオン） |
| 4688 | プロセス作成（コマンドライン監査が有効なら引数も） |
| 4720 / 4732 | ユーザ作成 / 管理者グループへの追加 |
| 7045 | サービスのインストール（PsExec 等） |
| 1102 | 監査ログの消去 |
| Sysmon 1 / 3 / 11 | プロセス作成 / ネットワーク接続 / ファイル作成 |

```bash
# Linux で evtx を読む
pip install python-evtx
evtx_dump.py Security.evtx | grep -A20 '<EventID>4625'
# 高速に検索・Sigma ルールで検知
chainsaw hunt ./logs/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml
hayabusa csv-timeline -d ./logs/ -o timeline.csv
```
