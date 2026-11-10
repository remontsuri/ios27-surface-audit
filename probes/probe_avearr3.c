/* probe_avearr3.c — третья волна: HEVCAuxiliaryLayerIDs.
 *
 * Вопросы:
 *  1) где граница количества (вторая проба: 8 — да, 17 — нет);
 *  2) валидируются ли ЗНАЧЕНИЯ (в 27.2 добавлено "layer_id_in_nuh is out of range");
 *  3) доходит ли это до AVE2 при реальном кодировании (set=0 этого не доказывает).
 *
 * Поэтому: фаза A — размеры 9/10/12/16, фаза B — 8 элементов с значениями вне
 * диапазона, фаза C — настоящее кодирование кадра 640x480 BGRA.
 * Лог пишется инкрементально, чтобы при панике демона было видно, на каком шаге.
 */
#include "kc_report.h"

typedef int int32_t_;
typedef unsigned int uint32_t_;
typedef unsigned long size_t_;
typedef const void *CFTypeRef;
typedef const void *CFAllocatorRef;
typedef const void *CFStringRef;
typedef const void *CFDictionaryRef;
typedef const void *CFNumberRef;
typedef const void *CFArrayRef;
typedef const void *VTCompressionSessionRef;
typedef const void *CVImageBufferRef;
typedef const void *CVPixelBufferRef;
typedef int32_t_ OSStatus;

typedef struct { long long value; int timescale; unsigned int flags; long long epoch; } CMTime;

#define KCFSTRING_UTF8 0x08000100
#define KCFNUMBER_INT  9
#define CODEC_HEVC     0x68766331
#define PIXFMT_BGRA    0x42475241

static void *CF, *VT, *CV;

static CFStringRef cfstr(const char *s)
{ return ((CFStringRef (*)(CFAllocatorRef, const char *, unsigned int))dlsym(CF, "CFStringCreateWithCString"))((CFAllocatorRef)0, s, KCFSTRING_UTF8); }
static CFNumberRef cfint(int v)
{ return ((CFNumberRef (*)(CFAllocatorRef, int, const void *))dlsym(CF, "CFNumberCreate"))((CFAllocatorRef)0, KCFNUMBER_INT, &v); }
static CFArrayRef cfarr(const void **vals, int n)
{ return ((CFArrayRef (*)(CFAllocatorRef, const void **, long, const void *))dlsym(CF, "CFArrayCreate"))((CFAllocatorRef)0, vals, n, (const void *)0); }

static void put(char *d, unsigned long cap, unsigned long *k, const char *s)
{ while (*s && *k < cap - 1) d[(*k)++] = *s++; }
static void putnum(char *d, unsigned long cap, unsigned long *k, long v)
{
    char t[24]; int n = 0; int neg = v < 0; unsigned long u = neg ? (unsigned long)(-v) : (unsigned long)v;
    if (!u) t[n++] = '0';
    while (u && n < 23) { t[n++] = (char)('0' + (u % 10)); u /= 10; }
    if (neg) put(d, cap, k, "-");
    while (n) { if (*k < cap - 1) d[(*k)++] = t[--n]; }
}

static VTCompressionSessionRef sess;
static OSStatus (*setp)(VTCompressionSessionRef, CFStringRef, CFTypeRef);
static char out[8000];
static unsigned long k;

#define KEYNAME "HEVCAuxiliaryLayerIDs"

static OSStatus set_ids(const int *vals, int n)
{
    const void *objs[64];
    int i;
    if (n > 64) return -999;
    for (i = 0; i < n; i++) objs[i] = (const void *)cfint(vals[i]);
    return setp(sess, cfstr(KEYNAME), (CFTypeRef)cfarr(objs, n));
}

static void note(const char *tag, int n, OSStatus s)
{
    put(out, sizeof out, &k, "\n"); put(out, sizeof out, &k, tag);
    put(out, sizeof out, &k, " n="); putnum(out, sizeof out, &k, n);
    put(out, sizeof out, &k, " set="); putnum(out, sizeof out, &k, s);
    out[k] = 0;
    kc_log("avearr3.log", out);
}

int main(int argc, char **argv)
{
    int i, n;
    int vals[64];
    k = 0;
    put(out, sizeof out, &k, "AVEARR3");

    CF = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", KC_RTLD_NOW);
    VT = dlopen("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox", KC_RTLD_NOW);
    CV = dlopen("/System/Library/Frameworks/CoreVideo.framework/CoreVideo", KC_RTLD_NOW);
    if (!CF || !VT) { put(out, sizeof out, &k, " dlopen_fail"); goto done; }

    OSStatus (*create)(CFAllocatorRef, int32_t_, int32_t_, uint32_t_, CFDictionaryRef,
                       CFDictionaryRef, CFAllocatorRef, void *, void *, VTCompressionSessionRef *) =
        (OSStatus (*)(CFAllocatorRef, int32_t_, int32_t_, uint32_t_, CFDictionaryRef,
                      CFDictionaryRef, CFAllocatorRef, void *, void *, VTCompressionSessionRef *))
        dlsym(VT, "VTCompressionSessionCreate");
    setp = (OSStatus (*)(VTCompressionSessionRef, CFStringRef, CFTypeRef))
        dlsym(VT, "VTSessionSetProperty");
    if (!create || !setp) { put(out, sizeof out, &k, " dlsym_fail"); goto done; }

    OSStatus st = create((CFAllocatorRef)0, 640, 480, CODEC_HEVC, (CFDictionaryRef)0,
                         (CFDictionaryRef)0, (CFAllocatorRef)0, (void *)0, (void *)0, &sess);
    put(out, sizeof out, &k, " create="); putnum(out, sizeof out, &k, st);
    if (st != 0 || !sess) goto done;

    OSStatus c = setp(sess, cfstr("NumberOfTemporalLayers"), (CFTypeRef)cfint(2));
    put(out, sizeof out, &k, " ctrl_ntl2="); putnum(out, sizeof out, &k, c);
    out[k] = 0; kc_log("avearr3.log", out);

    /* --- фаза A: где граница количества --- */
    {
        static const int sizes[] = {9, 10, 12, 16};
        for (i = 0; i < (int)(sizeof sizes / sizeof sizes[0]); i++) {
            int m = sizes[i];
            for (n = 0; n < m; n++) vals[n] = n;
            note("A_normal", m, set_ids(vals, m));
        }
    }

    /* --- фаза B: значения вне диапазона при n=8 --- */
    {
        static const int bad1[8] = {63, 64, 200, 255, 63, 63, 63, 63};
        static const int bad2[8] = {0, 1, 2, 3, 4, 5, 6, 7};
        static const int bad3[8] = {0, 1, 2, 3, 300, 400, 500, 600};
        static const int bad4[8] = {-1, -2, -3, -4, -5, -6, -7, -8};
        note("B_hi63",     8, set_ids(bad1, 8));
        note("B_normal",   8, set_ids(bad2, 8));
        note("B_hi300",    8, set_ids(bad3, 8));
        note("B_negative", 8, set_ids(bad4, 8));
    }

    /* --- фаза C: реальное кодирование, чтобы значение дошло до AVE2 --- */
    if (CV) {
        size_t_ (*pxcreate)(CFAllocatorRef, size_t_, size_t_, uint32_t_, CFDictionaryRef, CVPixelBufferRef *) =
            (size_t_ (*)(CFAllocatorRef, size_t_, size_t_, uint32_t_, CFDictionaryRef, CVPixelBufferRef *))
            dlsym(CV, "CVPixelBufferCreate");
        int (*lock)(CVPixelBufferRef, unsigned long) =
            (int (*)(CVPixelBufferRef, unsigned long))dlsym(CV, "CVPixelBufferLockBaseAddress");
        int (*unlock)(CVPixelBufferRef, unsigned long) =
            (int (*)(CVPixelBufferRef, unsigned long))dlsym(CV, "CVPixelBufferUnlockBaseAddress");
        void *(*base)(CVPixelBufferRef) = (void *(*)(CVPixelBufferRef))dlsym(CV, "CVPixelBufferGetBaseAddress");
        size_t_ (*bpr)(CVPixelBufferRef) = (size_t_ (*)(CVPixelBufferRef))dlsym(CV, "CVPixelBufferGetBytesPerRow");
        OSStatus (*encf)(VTCompressionSessionRef, CVImageBufferRef, CMTime, CMTime,
                         CFDictionaryRef, void *, unsigned int *) =
            (OSStatus (*)(VTCompressionSessionRef, CVImageBufferRef, CMTime, CMTime,
                          CFDictionaryRef, void *, unsigned int *))
            dlsym(VT, "VTCompressionSessionEncodeFrame");
        OSStatus (*complete)(VTCompressionSessionRef, CMTime *) =
            (OSStatus (*)(VTCompressionSessionRef, CMTime *))dlsym(VT, "VTCompressionSessionCompleteFrames");

        CVPixelBufferRef pb = 0;
        OSStatus st2 = pxcreate ? pxcreate((CFAllocatorRef)0, 640, 480, PIXFMT_BGRA,
                                           (CFDictionaryRef)0, &pb) : -1;
        put(out, sizeof out, &k, "\nC_pxbuf="); putnum(out, sizeof out, &k, st2);
        if (st2 == 0 && pb && lock && base) {
            lock(pb, 0);
            unsigned char *p = (unsigned char *)base(pb);
            unsigned long rows = bpr ? bpr(pb) : 640 * 4;
            if (p) { for (i = 0; i < (int)(rows * 480); i++) p[i] = (unsigned char)0x80; }
            if (unlock) unlock(pb, 0);

            /* выставляем 8 нормальных ID и кодируем три кадра */
            for (n = 0; n < 8; n++) vals[n] = n;
            note("C_pre_set", 8, set_ids(vals, 8));

            if (encf) {
                for (i = 0; i < 3; i++) {
                    CMTime pts; CMTime dur;
                    unsigned int flags = 0;
                    pts.value = i; pts.timescale = 30; pts.flags = 1; pts.epoch = 0;
                    dur.value = 1; dur.timescale = 30; dur.flags = 1; dur.epoch = 0;
                    OSStatus e = encf(sess, (CVImageBufferRef)pb, pts, dur, (CFDictionaryRef)0, (void *)0, &flags);
                    put(out, sizeof out, &k, "\nC_enc"); putnum(out, sizeof out, &k, i);
                    put(out, sizeof out, &k, "="); putnum(out, sizeof out, &k, e);
                    put(out, sizeof out, &k, " flags="); putnum(out, sizeof out, &k, flags);
                    out[k] = 0; kc_log("avearr3.log", out);
                }
                if (complete) {
                    OSStatus cf2 = complete(sess, (CMTime *)0);
                    put(out, sizeof out, &k, "\nC_complete="); putnum(out, sizeof out, &k, cf2);
                }
            } else {
                put(out, sizeof out, &k, " encf=absent");
            }
        }
    } else {
        put(out, sizeof out, &k, "\nCV dlopen fail");
    }

done:
    out[k] = 0;
    kc_log("avearr3.log", out);
    i = kc_post(out);
    kc_log("avearr3.log", i == 0 ? "post ok" : "post failed");
    kc_hold(argc, argv);
    return 0;
}
