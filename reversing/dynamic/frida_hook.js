// @desc:  Frida フックスクリプト（strcmp/memcmp 等の引数ログ、ptrace/IsDebuggerPresent 回避、任意アドレスでのレジスタ表示・戻り値書換）
// @tags:  ctf, reversing, dynamic, frida, hook, strcmp, memcmp, anti-debug, android, windows
// @deps:  frida-tools（pip install frida-tools）。Frida 16 / 17 両対応
// @usage: frida -q -l reversing/dynamic/frida_hook.js -f ./chall
//
// Linux / Windows / macOS / Android（ネイティブライブラリ）で同じスクリプトが動く。
// 下の CONFIG を書き換えて使う。標準入力が必要な場合は先に `frida -f` で起動し、端末にそのまま入力する。
//
// 任意アドレスのフック: Ghidra で見つけた関数オフセット（= アドレス - イメージベース）を HOOK_OFFSETS に書く。
//   例: Ghidra で check が 0x1011d6（PIE ELF のイメージベース 0x100000）→ offset 0x11d6

const CONFIG = {
  compareFuncs: ["strcmp", "strncmp", "strcasecmp", "memcmp", "bcmp", "strstr", "wcscmp", "lstrcmpA", "lstrcmpW"],
  maxLen: 128,
  antiDebug: true,   // ptrace(PTRACE_TRACEME) / IsDebuggerPresent / CheckRemoteDebuggerPresent を無効化
  onlyMainModule: true, // 本体モジュールからの呼び出しだけ表示
  // { offset: 0x11d6, name: "check", retval: 1, regs: true }
  //   retval を指定すると戻り値を書き換える / regs: true で全レジスタを表示
  HOOK_OFFSETS: [],
};

// ---- Frida 16 / 17 の API 差を吸収 ----
function findExport(name) {
  if (typeof Module.findGlobalExportByName === "function") return Module.findGlobalExportByName(name); // 17+
  return Module.findExportByName(null, name); // 16 以前
}
const mainModule = Process.mainModule || Process.enumerateModules()[0];

function fromMain(ctx) {
  if (!CONFIG.onlyMainModule) return true;
  const ra = ctx.returnAddress;
  return ra.compare(mainModule.base) >= 0 && ra.compare(mainModule.base.add(mainModule.size)) < 0;
}

function show(p, n, wide) {
  if (p.isNull()) return "NULL";
  try {
    if (n === undefined) {
      const s = wide ? p.readUtf16String() : p.readCString(); // NUL まで読む（size 指定すると NUL を越えて読む）
      return JSON.stringify(s.length > CONFIG.maxLen ? s.slice(0, CONFIG.maxLen) + "…" : s);
    }
    const bytes = new Uint8Array(p.readByteArray(Math.min(n, CONFIG.maxLen)));
    const printable = bytes.every((b) => b >= 0x20 && b < 0x7f);
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    return printable ? JSON.stringify(String.fromCharCode(...bytes)) : `hex:${hex}`;
  } catch (e) {
    return `<${p}>`;
  }
}

const hooked = new Set();

function hookCompare(name) {
  const addr = findExport(name);
  if (addr === null || hooked.has(addr.toString())) return; // memcmp と bcmp が同じ実体のことがある
  hooked.add(addr.toString());
  const withLen = ["strncmp", "memcmp", "bcmp"].includes(name);
  const isMem = ["memcmp", "bcmp"].includes(name);
  const wide = ["wcscmp", "lstrcmpW"].includes(name);
  Interceptor.attach(addr, {
    onEnter(args) {
      if (!fromMain(this)) return;
      const n = withLen ? args[2].toInt32() : undefined;
      const a = show(args[0], isMem ? n : undefined, wide);
      const b = show(args[1], isMem ? n : undefined, wide);
      const off = this.returnAddress.sub(mainModule.base);
      console.log(`[hook] ${name}(${a}, ${b}${withLen ? ", " + n : ""})  <- ${mainModule.name}+0x${off.toString(16)}`);
    },
  });
}

function bypassAntiDebug() {
  const ptrace = findExport("ptrace");
  if (ptrace !== null) {
    Interceptor.attach(ptrace, {
      onEnter(args) { this.traceme = args[0].toInt32() === 0; },
      onLeave(ret) {
        if (this.traceme) { ret.replace(ptr(0)); console.log("[anti-debug] ptrace(PTRACE_TRACEME) -> 0"); }
      },
    });
  }
  for (const name of ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]) {
    const f = findExport(name);
    if (f === null) continue;
    Interceptor.attach(f, {
      onEnter(args) { this.out = name === "CheckRemoteDebuggerPresent" ? args[1] : null; },
      onLeave(ret) {
        if (this.out) this.out.writeU32(0);
        ret.replace(ptr(0));
      },
    });
    console.log(`[anti-debug] ${name} -> 0`);
  }
}

function hookOffsets() {
  for (const h of CONFIG.HOOK_OFFSETS) {
    const addr = mainModule.base.add(h.offset);
    Interceptor.attach(addr, {
      onEnter(args) {
        console.log(`[offset] ${h.name || addr} called  args: ${args[0]}, ${args[1]}, ${args[2]}`);
        console.log(`         arg0 as string: ${show(args[0])}`);
        if (h.regs) console.log(`         ${JSON.stringify(this.context)}`);
      },
      onLeave(ret) {
        console.log(`[offset] ${h.name || addr} returned ${ret}`);
        if (h.retval !== undefined) { ret.replace(ptr(h.retval)); console.log(`         -> ${h.retval} に書き換え`); }
      },
    });
  }
}

console.log(`[*] main module: ${mainModule.name} @ ${mainModule.base} (${Process.arch}, ${Process.platform})`);
CONFIG.compareFuncs.forEach(hookCompare);
if (CONFIG.antiDebug) bypassAntiDebug();
hookOffsets();
