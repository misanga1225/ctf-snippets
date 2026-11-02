# 🧮 reversing/solve — シンボリック実行・ソルバ

静的・動的解析でわかった判定ロジックから、**正解の入力を逆算する**段階です。
「手で逆算する」「Z3 に解かせる」「angr に丸投げする」「サイドチャネルで 1 文字ずつ当てる」の 4 通りを状況で使い分けます。

← [static/](../static/README.md)・[dynamic/](../dynamic/README.md) ／ [reversing/README.md](../README.md)

---

## 目次

- [どの方法で解くか](#どの方法で解くか)
- [スクリプト一覧](#スクリプト一覧)
- [スクリプトの詳しい使い方](#スクリプトの詳しい使い方)
  - [angr_solve.py](#angr_solvepy) / [z3_template.py](#z3_templatepy) / [sidechannel_brute.py](#sidechannel_brutepy)
- [手で逆算する（Python）](#手で逆算するpython)
- [angr の応用スニペット](#angr-の応用スニペット)
- [Z3 の書き方メモ](#z3-の書き方メモ)
- [その他の手段](#その他の手段)

---

## どの方法で解くか

| 判定ロジックの特徴 | 方法 | 所要時間の目安 |
|---|---|---|
| 1 文字ずつ独立した可逆な変換（XOR・加算・テーブル置換） | **手で逆算**（Python 数行） | 数分 |
| 文字同士が絡む連立式・ビット演算の組み合わせ | **Z3**（`z3_template.py` に書き写す） | 10〜30 分 |
| 分岐が多い / 読むのが面倒 / 入力長が短め | **angr**（`angr_solve.py`） | 数秒〜数分（解けないこともある） |
| 先頭から比較して不一致で即 return | **サイドチャネル**（`sidechannel_brute.py`） | 数分 |
| ハッシュ（MD5 / SHA / CRC）を通して比較 | 総当たり（入力空間が小さい時のみ）・CRC は Z3 で解ける | — |
| 標準暗号（AES / RC4 / TEA）で暗号化して比較 | 鍵を見つけて**復号**（pycryptodome） | — |

---

## スクリプト一覧

<!-- SNIPPETS:START -->

### 🧮 reversing/solve — シンボリック実行・ソルバ

| スクリプト | 用途 | 依存 | 使用例 |
|---|---|---|---|
| [`angr_solve.py`](angr_solve.py) | angr のシンボリック実行で「成功メッセージに到達する入力」を自動探索（stdin / argv 入力、文字列 or アドレスで find/avoid 指定） | angr（pip install angr。Python 3.10〜3.12 推奨） | `python3 reversing/solve/angr_solve.py ./chall --find Correct --avoid Wrong --len 32` |
| [`sidechannel_brute.py`](sidechannel_brute.py) | 実行命令数のサイドチャネルで flag を 1 文字ずつ総当たり（先頭から比較して不一致で抜ける実装に有効。perf / valgrind） | perf（linux-tools）または valgrind | `python3 reversing/solve/sidechannel_brute.py ./chall --len 19 --prefix 'flag{' --success Correct` |
| [`z3_template.py`](z3_template.py) | Z3 で「逆コンパイルした判定ロジック」を制約として書いて flag を解くテンプレート（XOR・加算・ローテート・連立式・全解列挙の例つき） | z3-solver（pip install z3-solver） | `python3 reversing/solve/z3_template.py [--all]` |

<!-- SNIPPETS:END -->

---

## スクリプトの詳しい使い方

### angr_solve.py

シンボリック実行で「成功の出力（またはアドレス）に到達し、失敗には到達しない入力」を自動で探します。

```bash
# 標準入力から読む crackme（最頻出）
python3 reversing/solve/angr_solve.py ./chall --find 'Correct' --avoid 'Wrong' --len 32
# 印字可能文字 + 既知の先頭で探索空間を絞る
python3 reversing/solve/angr_solve.py ./chall --find 'Correct' --avoid 'Wrong' --len 32 --printable --prefix 'flag{'
# argv[1] で受け取るタイプ
python3 reversing/solve/angr_solve.py ./chall --argv --find 'Correct' --avoid 'Wrong' --len 24
# アドレスで指定（Ghidra のアドレスをそのまま使う）
python3 reversing/solve/angr_solve.py ./chall --base 0x100000 --find 0x101397 --avoid 0x1013a8 --len 19
# 判定関数 check(char *s) だけを解く（main の前処理が重い / 入力経路が特殊な場合）
python3 reversing/solve/angr_solve.py ./chall --base 0x100000 --start 0x1011d6 --find 0x101276 --avoid 0x10121e --len 19
```

```
[*] AMD64, base 0x400000, entry 0x4010f0
[*] exploring ...
[*] 0.2s  <SimulationManager with 1 found, 15 avoid>
[+] input : b'flag{r3v_w1th_sn1p}'
[+] stdout: b'password: Correct!\n'
```

| オプション | 意味 |
|---|---|
| `--find` / `--avoid` | 出力に含まれる文字列 or アドレス（`0x` 始まり）。複数指定可 |
| `--len N` | 入力の長さ。**strlen チェックがあるなら正確に**（違うと解けない） |
| `--printable` / `--charset` / `--prefix` | 入力の制約。探索が速くなる |
| `--argv` | 入力を argv[1] で渡す |
| `--newline` | stdin の末尾に改行を付ける（既定は付けず EOF。angr 10 の fgets は改行付きだと解けないことがあった） |
| `--base` | PIE のロードベース（Ghidra 準拠なら `0x100000`、objdump 準拠なら `0`） |
| `--start ADDR` | その関数から実行開始。入力は第 1 引数（rdi / x0）にポインタで渡す |
| `--veritesting` | 状態爆発を抑える探索法 |
| `--timeout` | 打ち切り秒数（既定 600） |

**解けないとき**: `--len` を確認 → `--avoid` を増やす（エラー表示・`exit` 呼び出し） → `--start` で判定関数だけを対象にする → ハッシュ・暗号を含むなら angr ではなく別の方法。

---

### z3_template.py

逆コンパイルした判定ロジックを Z3 の制約として書き写すテンプレートです。そのまま実行するとサンプル問題（XOR）が解けます。

```bash
pip install z3-solver
cp reversing/solve/z3_template.py solve.py     # コピーして編集
python3 solve.py                               # 解を 1 つ
python3 solve.py --all --max 50                # 全解を列挙（制約が足りているかの確認）
```

編集するのは `FLAG_LEN`・`ENC`（`extract_bytes.py -f py` の出力を貼る）・`add_constraints()` の中身だけです。

```python
# Ghidra:  if ((s[i] ^ (i*7+0x13)) != enc[i]) return 0;
for i in range(FLAG_LEN):
    s.add(f[i] ^ BitVecVal((i * 7 + 0x13) & 0xFF, 8) == ENC[i])
```

---

### sidechannel_brute.py

「先頭から 1 文字ずつ比較して、違ったらすぐ return」する実装は、**正しい文字が多いほど実行命令数が増えます**。
これを perf / valgrind で数えて 1 文字ずつ確定させます。ロジックを読まなくても解けるのが利点です。

```bash
# perf（速い。ベアメタル / VM。コンテナでは使えないことが多い）
python3 reversing/solve/sidechannel_brute.py ./chall --len 19 --prefix 'flag{' --success Correct
# valgrind（遅いがどこでも動く）
python3 reversing/solve/sidechannel_brute.py ./chall --len 19 --prefix 'flag{' --success Correct --counter valgrind -j 8
# argv で受け取る / 文字種を絞る
python3 reversing/solve/sidechannel_brute.py ./chall --argv --len 16 --charset 0123456789abcdef
```

```
[*] counter=valgrind  charset=71 chars
[*] baseline 115670 instructions
[  6/19] flag{r               (115694 vs median 115670, +24)
[  7/19] flag{r3              (115718 vs median 115694, +24)
...
[+] success: flag{r3v_w1th_sn1p}
```

- `perf` が使えない場合: `sudo sysctl kernel.perf_event_paranoid=1` を試すか `--counter valgrind`
- 差が出ない場合は、全文字を比較してから判定している / memcmp で一括比較している（効かない実装）
- 長さチェックがあるなら `--len` を正確に（長さ違いで即 return すると全候補が同じ命令数になる）

---

## 手で逆算する（Python）

1 文字ずつ独立した変換なら、逆変換を書くのが一番速くて確実です。

```python
enc = [0x75, 0x76, 0x40, ...]        # extract_bytes.py -f py の出力

# XOR（自分自身が逆）: out[i] = in[i] ^ key[i % len(key)]
print(bytes(c ^ key[i % len(key)] for i, c in enumerate(enc)))

# 加算 → 減算: out[i] = (in[i] + k) & 0xff
print(bytes((c - k) & 0xFF for c in enc))

# ローテート → 逆ローテート: out = rol8(in, 3)
ror8 = lambda x, n: ((x >> n) | (x << (8 - n))) & 0xFF
print(bytes(ror8(c, 3) for c in enc))

# テーブル置換 → 逆テーブル: out[i] = table[in[i]]
inv = {v: i for i, v in enumerate(table)}
print(bytes(inv[c] for c in enc))

# 1 つ前の出力に依存（CBC 風）: out[i] = in[i] ^ out[i-1]
print(bytes(c ^ (enc[i - 1] if i else iv) for i, c in enumerate(enc)))

# 1 文字ずつ独立なら総当たりでも OK（逆関数を考えなくていい）
def f(i, ch): return (ch * 7 + i) & 0xFF       # 判定式を書き写す
print(bytes(next(ch for ch in range(256) if f(i, ch) == e) for i, e in enumerate(enc)))
```

標準暗号は鍵を見つけたらライブラリで復号します:

```python
from Crypto.Cipher import AES, ARC4     # pip install pycryptodome
AES.new(key, AES.MODE_ECB).decrypt(enc)
AES.new(key, AES.MODE_CBC, iv).decrypt(enc)
ARC4.new(key).decrypt(enc)
```

---

## angr の応用スニペット

`angr_solve.py` で足りない場合に自分で書くための部品です。

```python
import angr
try:
    import claripy
except ImportError:
    from angr import claripy            # angr 10 以降

proj = angr.Project("./chall", auto_load_libs=False)

# 関数を差し替える（重い処理・アンチデバッグ・未対応の関数）
class Ret0(angr.SimProcedure):
    def run(self, *args):
        return 0
proj.hook_symbol("ptrace", Ret0())
proj.hook_symbol("sleep", Ret0())
proj.hook(0x401234, Ret0(), length=5)   # 特定の call 命令（5 バイト）をスキップ

# グローバル変数・メモリを記号化
state = proj.factory.entry_state()
key = claripy.BVS("key", 8 * 16)
state.memory.store(0x404060, key)

# レジスタに記号値（関数の途中から始める）
state = proj.factory.blank_state(addr=0x4011d6)
x = claripy.BVS("x", 64)
state.regs.rdi = x

# ファイル入力
content = claripy.BVS("file", 8 * 64)
state.fs.insert("key.txt", angr.SimFile("key.txt", content=content))

# 探索
simgr = proj.factory.simgr(state)
simgr.explore(find=0x401300, avoid=[0x401310, 0x401320])
if simgr.found:
    s = simgr.found[0]
    print(s.solver.eval(key, cast_to=bytes))
    print(s.solver.eval_upto(x, 5))     # 解を最大 5 個
```

---

## Z3 の書き方メモ

| C のコード | Z3 |
|---|---|
| `unsigned char c` | `BitVec('c', 8)` |
| `int x`（32bit） | `BitVec('x', 32)` |
| `(int)c`（char → int への昇格） | `ZeroExt(24, c)`（unsigned char）/ `SignExt(24, c)`（signed char） |
| `x >> 3`（unsigned） | `LShR(x, 3)`（`>>` は算術シフト） |
| `x / y`, `x % y`（unsigned） | `UDiv(x, y)`, `URem(x, y)` |
| `x < y`（unsigned） | `ULT(x, y)`（`<` は符号付き） |
| `(x << 3) \| (x >> 5)`（8bit） | `RotateLeft(x, 3)` |
| `(uint8_t)x` | `Extract(7, 0, x)` |
| `a && b`, `a \|\| b`, `!a` | `And(a, b)`, `Or(a, b)`, `Not(a)` |
| `cond ? a : b` | `If(cond, a, b)` |
| `table[c]`（定数テーブル） | `Array` を作るか、`If` の連鎖: `reduce(lambda acc, i: If(c == i, table[i], acc), range(256), 0)` |

```python
from z3 import *
s = Solver()
x = BitVec("x", 32)
s.add(x * 0x1337 + 0xdead == 0xcafebabe)
print(s.check(), s.model()[x])          # sat / 値
# 最適化（最小値を求める）
o = Optimize(); o.add(x > 100); o.minimize(x); o.check(); print(o.model())
```

---

## その他の手段

| 手段 | 使いどころ |
|---|---|
| pwntools でリモートに総当たり | 判定結果がネットワーク越しに返ってくる問題 |
| Unicorn / Qiling | 判定関数だけをエミュレーションで高速に何万回も実行して総当たり |
| GDB で判定関数を何度も呼ぶ | `call (int)check("flag{aaaa}")` で 1 文字ずつ試す |
| パッチして表示させる | flag を復号して表示する処理があるが、条件で隠されている時（[patch_bytes.py](../static/README.md#patch_bytespy)） |
| hashcat / john | 入力のハッシュと比較している（辞書・短い入力） |
