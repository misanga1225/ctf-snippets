# 🔤 encoding — エンコード / デコード

CTF で渡される「謎の文字列」や、Reversing・Forensics の途中で出てくるエンコードされたデータを変換するスクリプト集です。
すべて **Python 標準ライブラリのみ**で動き、入力はコマンド引数か標準入力（パイプ）から受け取ります。

← [README.md（トップ）](../README.md)

---

## 目次

- [まず何をするか](#まず何をするか)
- [スクリプト一覧](#スクリプト一覧)
- [スクリプトの詳しい使い方](#スクリプトの詳しい使い方)
  - [auto_decode.py](#auto_decodepy) / [b64.py](#b64py) / [hexconv.py](#hexconvpy) / [rot.py](#rotpy) / [urlenc.py](#urlencpy) / [xor.py](#xorpy)
- [パイプでつなぐ](#パイプでつなぐ)
- [見た目から形式を判断する](#見た目から形式を判断する)
- [外部コマンド集](#外部コマンド集)

---

## まず何をするか

```bash
python3 encoding/auto_decode.py '<謎の文字列>'     # 多段エンコードを自動判定
python3 encoding/hexconv.py -f hex '<16進>'         # hex を全形式で眺める
```

自動判定で出なければ、[見た目から形式を判断する](#見た目から形式を判断する) の表を見て個別のスクリプトを使います。

---

## スクリプト一覧

<!-- SNIPPETS:START -->

### 🔤 encoding — エンコード / デコード

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`auto_decode.py`](auto_decode.py) | 多段エンコードを自動判定してデコード（CyberChef Magic 簡易版、flag 形式を検出） | none | `python3 encoding/auto_decode.py 'NjY2YzYxNjc3Yjc4N2Q='` |
| [`b64.py`](b64.py) | base64 / base32 / base85 / ascii85 / base58 のエンコード・デコード | none | `echo 'ZmxhZ3t4fQ==' \| python3 encoding/b64.py -d` |
| [`hexconv.py`](hexconv.py) | hex / bytes / 整数 / 2進数 / 10進バイト列の相互変換 | none | `python3 encoding/hexconv.py -f hex -t str 666c61677b787d` |
| [`rot.py`](rot.py) | ROT13 / ROT-N / ROT47 / Caesar 全シフト総当たり | none | `python3 encoding/rot.py --brute 'synt{ebg13}'` |
| [`urlenc.py`](urlenc.py) | URL エンコード / デコード（多重エンコードの完全デコード対応） | none | `python3 encoding/urlenc.py -d --full '%2566lag%257B%2578%257D'` |
| [`xor.py`](xor.py) | XOR（単一/複数バイト鍵）、単一バイト鍵の総当たり、既知平文からの鍵推定 | none | `python3 encoding/xor.py -k 0x42 -i hex 242e2325393a3f` |

<!-- SNIPPETS:END -->

---

## スクリプトの詳しい使い方

### auto_decode.py

hex / base32 / base64 / base64url / base58 / base85 / 2 進数 / 10 進数列 / URL / ROT13 を総当たりで重ねて試し、**flag 形式（`xxx{...}`）が出たデコード経路**を表示します（CyberChef の Magic の簡易版）。

```bash
python3 encoding/auto_decode.py 'NjY2YzYxNjc3Yjc4N2Q='
# [base64 -> hex] flag{x}
# [base64 -> hex -> rot13] synt{k}

echo 'NjY2YzYx...' | python3 encoding/auto_decode.py          # stdin
python3 encoding/auto_decode.py -f 'CTF\{[^}]+\}' '<data>'     # flag 形式を指定（正規表現）
python3 encoding/auto_decode.py --depth 12 '<data>'            # 最大段数（default: 8）
```

---

### b64.py

base64 / base64url / base32 / base85 / ascii85 / base58 のエンコード・デコード。パディング（`=`）が欠けていても補完します。

```bash
python3 encoding/b64.py -d 'ZmxhZ3t4fQ'            # デコード（-d は省略可）
python3 encoding/b64.py -e 'flag{x}'               # エンコード
python3 encoding/b64.py -v 32 -d 'MZWGCZ33PB6Q'    # base32
python3 encoding/b64.py -v 58 -d '...'             # base58（ビットコインアドレス形式）
python3 encoding/b64.py -v a85 -d '<~...~>'        # ascii85（<~ ~> 付きでも可）
python3 encoding/b64.py -v 64url -d 'eyJhbGciOi'   # base64url（JWT など）
python3 encoding/b64.py -n 5 -d '<5重base64>'      # 繰り返しデコード
```

| `-v` | 文字種 | 見た目の特徴 |
|---|---|---|
| `64`（既定） | `A-Za-z0-9+/` | 末尾 `=`、長さが 4 の倍数 |
| `64url` | `A-Za-z0-9-_` | JWT・URL 内 |
| `32` | `A-Z2-7` | 大文字と数字のみ、末尾 `======` |
| `85` | 記号を多く含む | Python の b85 |
| `a85` | `!`〜`u` | `<~ ... ~>` で囲まれることがある |
| `58` | `0OIl` を含まない英数字 | ビットコイン |

> 独自の変換テーブル（並び替えた base64）の場合は Python で: `base64.b64decode(s.translate(str.maketrans(CUSTOM, STD)))`

---

### hexconv.py

hex / 文字列 / 整数 / 2 進数 / 10 進バイト列を相互変換します。`-t` を省略すると全形式を表示します。

```bash
python3 encoding/hexconv.py -f hex 666c61677b787d
#   str: flag{x}
#   hex: 666c61677b787d
#   int: 28829613228259453
#   bin: 01100110 01101100 ...
#   dec: 102 108 97 103 123 120 125
# pyhex: \x66\x6c\x61\x67\x7b\x78\x7d

python3 encoding/hexconv.py -f int -t str 28829613228259453     # RSA で復号した整数 → 文字列
python3 encoding/hexconv.py -f dec -t str '102 108 97 103'       # ASCII コード列 → 文字列
python3 encoding/hexconv.py -f bin -t str '01100110 01101100'    # 2 進数 → 文字列
python3 encoding/hexconv.py -f str -t hex 'flag'                 # 文字列 → hex
python3 encoding/hexconv.py -f hex '0x66,0x6c,0x61'              # 0x / \x / 区切り文字は自動で除去
```

---

### rot.py

ROT13 / 任意シフトの Caesar / ROT47。

```bash
python3 encoding/rot.py 'synt{ebg13}'                       # ROT13
python3 encoding/rot.py -n 23 'iodj{fdhvdu}'                # ROT-N（-n は進める数。+3 されたものは 26-3=23 で戻る）
python3 encoding/rot.py --brute 'iodj{fdhvdu}'              # 1〜25 の全シフト
python3 encoding/rot.py --brute --grep flag 'iodj{fdhvdu}'  # flag を含む結果だけ
python3 encoding/rot.py --rot47 '7=28LC@EcfN'               # ROT47（記号も回転）
```

---

### urlenc.py

URL エンコード / デコード。多重エンコード（`%2541` → `%41` → `A`）を最後まで戻せます。

```bash
python3 encoding/urlenc.py -d '%66%6c%61%67'
python3 encoding/urlenc.py -d --full '%2566lag%257B%2578%257D'   # 変化しなくなるまで繰り返す
python3 encoding/urlenc.py -d --plus 'a+b%3Dc'                  # + を空白として扱う（フォーム）
python3 encoding/urlenc.py -e 'a b&c'                            # エンコード
python3 encoding/urlenc.py -e --all 'flag'                       # 英数字も含め全部 %XX に
```

---

### xor.py

XOR の暗号化/復号、単一バイト鍵の総当たり、既知平文からの鍵推定。

```bash
python3 encoding/xor.py -k 0x42 -i hex 242e2325393a3f            # hex 入力を鍵 0x42 で XOR
python3 encoding/xor.py -k 'key' < enc.bin > dec.bin            # 文字列鍵（繰り返し）でファイルを復号
python3 encoding/xor.py --brute -i hex 242e2325393a3f            # 単一バイト鍵を総当たり
# 0x42 (100%): flag{x}
python3 encoding/xor.py --known 'flag{' -i hex 242e2325393a3f    # 先頭が flag{ と仮定して鍵を推定
# key (hex): 4242424242  key (str): b'BBBBB'
python3 encoding/xor.py -k 0x42 -o hex 'flag{x}'                 # 出力を hex で
```

`--known` で出た鍵が `BBBBB` のように**繰り返し**になっていれば単一バイト鍵、`keyke` のようになっていれば繰り返し鍵（この例では `key`）です。

---

## パイプでつなぐ

各スクリプトは stdin を読み stdout に書くので、多段の変換をパイプでつなげられます。

```bash
# base64 → XOR(0x42)
echo 'JC4jJTk6Pw==' | encoding/b64.py -d | encoding/xor.py -k 0x42
# hex → base64 → ROT13
echo '...' | encoding/hexconv.py -f hex -t str | encoding/b64.py -d | encoding/rot.py
# ファイルのバイナリを XOR 復号して種類を判定
encoding/xor.py -k 0x5a < enc.bin > dec.bin && file dec.bin
```

---

## 見た目から形式を判断する

| 見た目 | 形式 | 使うもの |
|---|---|---|
| `0-9a-f` のみ、偶数長 | hex | `hexconv.py -f hex` |
| `A-Za-z0-9+/`、末尾 `=` | base64 | `b64.py -d` |
| `A-Z2-7`、末尾 `====` | base32 | `b64.py -v 32 -d` |
| `<~ ... ~>` | ascii85 | `b64.py -v a85 -d` |
| `0` と `1` と空白 | 2 進数 | `hexconv.py -f bin` |
| `102 108 97 103` | 10 進 ASCII コード | `hexconv.py -f dec` |
| `%XX` を含む | URL エンコード | `urlenc.py -d --full` |
| `synt{...}` / `iodj{...}` | ROT13 / Caesar | `rot.py --brute --grep flag` |
| 記号だらけの ASCII | ROT47 / base85 | `rot.py --rot47` / `b64.py -v 85` |
| `.-- ..- ...` | モールス信号 | CyberChef: From Morse Code |
| `&#x66;` / `&#102;` | HTML エンティティ | `python3 -c 'import html,sys;print(html.unescape(sys.argv[1]))' '...'` |
| `f` | Unicode エスケープ | `python3 -c 'import sys;print(sys.argv[1].encode().decode("unicode_escape"))' '...'` |
| `=66=6C` | Quoted-Printable | `python3 -c 'import quopri,sys;print(quopri.decodestring(sys.argv[1]))' '...'` |
| `begin 644 ...` | uuencode | `uudecode` |
| `eyJ` で始まる | JSON の base64（JWT） | `b64.py -v 64url -d` |
| `H4sI` で始まる | gzip の base64 | `b64.py -d | gunzip` |
| `UEsDB` で始まる | ZIP の base64 | `b64.py -d > x.zip` |
| `iVBORw0KGgo` で始まる | PNG の base64 | `b64.py -d > x.png` |
| `TVqQ` で始まる | PE (exe) の base64 | `b64.py -d > x.exe` |
| 印字不可のバイナリ | XOR / 暗号 | `xor.py --brute` / `--known flag{` |

---

## 外部コマンド集

```bash
# base64
echo 'ZmxhZ3t4fQ==' | base64 -d          # macOS は base64 -D（新しい macOS は -d も可）
echo -n 'flag{x}' | base64
# base32
echo 'MZWGCZ33PB6Q====' | base32 -d     # GNU coreutils
# hex
echo '666c6167' | xxd -r -p              # hex → バイナリ
echo -n 'flag' | xxd -p                  # バイナリ → hex
printf '\x66\x6c\x61\x67'                # エスケープ → バイナリ
# ROT13
echo 'synt' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# 文字コード変換
iconv -f UTF-16LE -t UTF-8 in.txt
iconv -f SHIFT_JIS -t UTF-8 in.txt       # 文字化けした日本語
# ハッシュ
echo -n 'flag' | md5sum / sha1sum / sha256sum
# 1 行 Python
python3 -c 'print(bytes.fromhex("666c6167"))'
python3 -c 'import base64;print(base64.b64decode("ZmxhZw=="))'
python3 -c 'print(int.to_bytes(28829613228259453, 7, "big"))'
```

**CyberChef**（https://gchq.github.io/CyberChef/）: ブラウザで変換を組み合わせられる定番ツール。「Magic」で自動判定、オフライン版もダウンロード可能。
