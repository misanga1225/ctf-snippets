// @desc:  LD_PRELOAD 用フックライブラリ（strcmp/memcmp 等の引数ログ、ptrace アンチデバッグ回避、sleep 無効化、time/rand の固定）
// @tags:  ctf, reversing, dynamic, ld_preload, hook, strcmp, memcmp, anti-debug, ptrace, rand, time
// @deps:  gcc（対象が動的リンクされた Linux バイナリであること）
// @usage: gcc -shared -fPIC -O2 -o hook.so reversing/dynamic/ld_preload_hook.c -ldl && LD_PRELOAD=./hook.so ./chall
//
// gdb が使えない / アンチデバッグが多い / 大量に試行したい時に便利。ログは stderr に出る。
//
// 環境変数:
//   HOOK_QUIET=1      比較関数のログを出さない（ptrace 回避や time 固定だけ使う）
//   FAKE_TIME=<n>     time() / gettimeofday の秒を n に固定（srand(time(NULL)) 系の問題で乱数を再現）
//   FAKE_SEED=<n>     srand() に渡る seed を n に差し替え（元の seed はログに出る）
//   KEEP_SLEEP=1      sleep / usleep / nanosleep を本当に待つ（既定は即 return）
//
// 効かないケース: 静的リンク / 比較がインライン展開 / 自前ループ比較 / syscall 直呼び（→ gdb か Frida）
// 32bit バイナリには gcc -m32 で 32bit 版を作る（gcc-multilib が必要）

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define REAL(name) \
    static __typeof__(name) *real_##name; \
    if (!real_##name) real_##name = (__typeof__(name) *)dlsym(RTLD_NEXT, #name)

static __thread int in_hook;  // ログ出力中に自分自身が呼ばれても無限再帰しないように

static int quiet(void) { return getenv("HOOK_QUIET") != NULL; }

// 印字可能ならそのまま、そうでなければ \xNN でエスケープして buf に追記
static size_t dump(char *buf, size_t pos, size_t cap, const unsigned char *p, size_t n, int stop_at_nul) {
    pos += snprintf(buf + pos, cap - pos, "\"");
    for (size_t i = 0; i < n && i < 256 && pos + 8 < cap; i++) {
        if (stop_at_nul && !p[i]) break;
        if (p[i] >= 0x20 && p[i] < 0x7f && p[i] != '"' && p[i] != '\\') buf[pos++] = (char)p[i];
        else pos += snprintf(buf + pos, cap - pos, "\\x%02x", p[i]);
    }
    pos += snprintf(buf + pos, cap - pos, "\"");
    return pos;
}

// 1 行を組み立ててから一度に書く（プログラム自身の出力と混ざりにくくする）
static void log_cmp(const char *fn, const void *a, const void *b, long n, int is_str, void *caller) {
    if (in_hook || quiet()) return;
    in_hook = 1;
    char buf[2048];
    size_t pos = snprintf(buf, sizeof buf, "\033[1;33m[hook]\033[0m %s(", fn);
    pos = dump(buf, pos, sizeof buf, a, is_str ? 256 : (size_t)n, is_str);
    pos += snprintf(buf + pos, sizeof buf - pos, ", ");
    pos = dump(buf, pos, sizeof buf, b, is_str ? 256 : (size_t)n, is_str);
    if (n >= 0) pos += snprintf(buf + pos, sizeof buf - pos, ", %ld", n);
    snprintf(buf + pos, sizeof buf - pos, ")  <- %p\n", caller);
    fputs(buf, stderr);
    in_hook = 0;
}

int strcmp(const char *a, const char *b) {
    REAL(strcmp);
    log_cmp("strcmp", a, b, -1, 1, __builtin_return_address(0));
    return real_strcmp(a, b);
}

int strncmp(const char *a, const char *b, size_t n) {
    REAL(strncmp);
    log_cmp("strncmp", a, b, (long)n, 1, __builtin_return_address(0));
    return real_strncmp(a, b, n);
}

int strcasecmp(const char *a, const char *b) {
    REAL(strcasecmp);
    log_cmp("strcasecmp", a, b, -1, 1, __builtin_return_address(0));
    return real_strcasecmp(a, b);
}

int memcmp(const void *a, const void *b, size_t n) {
    REAL(memcmp);
    log_cmp("memcmp", a, b, (long)n, 0, __builtin_return_address(0));
    return real_memcmp(a, b, n);
}

int bcmp(const void *a, const void *b, size_t n) {  // gcc は memcmp(...)==0 を bcmp に変換することがある
    REAL(memcmp);
    log_cmp("bcmp", a, b, (long)n, 0, __builtin_return_address(0));
    return real_memcmp(a, b, n);
}

char *strstr(const char *h, const char *n) {
    REAL(strstr);
    log_cmp("strstr", h, n, -1, 1, __builtin_return_address(0));
    return real_strstr(h, n);
}

// ---- アンチデバッグ回避: ptrace(PTRACE_TRACEME) は常に成功させる ----
long ptrace(enum __ptrace_request req, ...) {
    va_list ap;
    va_start(ap, req);
    pid_t pid = va_arg(ap, pid_t);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    if (req == PTRACE_TRACEME) {
        fprintf(stderr, "\033[1;35m[anti-debug]\033[0m ptrace(PTRACE_TRACEME) -> 0\n");
        return 0;
    }
    REAL(ptrace);
    return real_ptrace(req, pid, addr, data);
}

// ---- 時間稼ぎ・タイミングチェック対策 ----
unsigned int sleep(unsigned int s) {
    if (getenv("KEEP_SLEEP")) { REAL(sleep); return real_sleep(s); }
    fprintf(stderr, "[hook] sleep(%u) skipped\n", s);
    return 0;
}

int usleep(useconds_t us) {
    if (getenv("KEEP_SLEEP")) { REAL(usleep); return real_usleep(us); }
    return 0;
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
    if (getenv("KEEP_SLEEP")) { REAL(nanosleep); return real_nanosleep(req, rem); }
    if (rem) rem->tv_sec = rem->tv_nsec = 0;
    return 0;
}

time_t time(time_t *t) {
    const char *f = getenv("FAKE_TIME");
    REAL(time);
    time_t v = f ? (time_t)strtoll(f, NULL, 0) : real_time(NULL);
    if (t) *t = v;
    if (!quiet()) fprintf(stderr, "[hook] time() = %lld\n", (long long)v);
    return v;
}

int gettimeofday(struct timeval *tv, void *tz) {
    REAL(gettimeofday);
    int r = real_gettimeofday(tv, tz);
    const char *f = getenv("FAKE_TIME");
    if (f) { tv->tv_sec = (time_t)strtoll(f, NULL, 0); tv->tv_usec = 0; }
    return r;
}

void srand(unsigned int seed) {
    REAL(srand);
    const char *f = getenv("FAKE_SEED");
    unsigned int s = f ? (unsigned int)strtoul(f, NULL, 0) : seed;
    if (!quiet() || f) fprintf(stderr, "[hook] srand(%u)%s\n", seed, f ? " -> FAKE_SEED" : "");
    real_srand(s);
}
