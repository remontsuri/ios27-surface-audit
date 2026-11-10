/*
 * probe_tiff.c - decode TIFF fixtures through ImageIO on the device.
 *
 * Why: on 24A446 `TIFFReadPlugin::decodeTilePlanar` copies a row into the
 * destination without checking "destination row >= required scatter" (27.2 added
 * that check, with the string "destination row is %u bytes, the scatter needs
 * %llu"). If the scatter can be raised from the file (SamplesPerPixel /
 * BitsPerSample / Photometric + planar + tiled), the copy writes past the row.
 *
 * What the probe does:
 *   - reads Documents/list.txt (one name per line);
 *   - takes the start index from Documents/cursor.txt and writes the NEXT index
 *     immediately, so that after a process crash a restart continues with the
 *     following file;
 *   - for each file: CGImageSourceCreateWithURL -> properties ->
 *     CGImageSourceCreateImageAtIndex -> forced draw into a bitmap
 *     (ImageIO is lazy: without a draw the decoder may never run)
 *     -> FNV hash of the pixels plus a count of non-zero bytes;
 *   - additionally tries the thumbnail path;
 *   - every log line is flushed to disk (fflush + fsync).
 *
 * Log format: one line per event, fields separated by spaces, prefixes:
 *   TIFF start / FILE <i> <name> / PROPS ... / IMG ... / THUMB ... / DONE / ERR ...
 */
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static FILE *g;
static char g_base[512];

static void L(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g, fmt, ap);
    va_end(ap);
    fputc('\n', g);
    fflush(g);
    fsync(fileno(g));
}

static unsigned long fnv1a(const unsigned char *p, size_t n) {
    unsigned long h = 1469598103934665603UL;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211UL;
    }
    return h;
}

/* Pull a number out of the properties dictionary by key. Returns -1 if absent. */
static long prop_long(CFDictionaryRef d, CFStringRef key) {
    if (!d) return -1;
    CFTypeRef v = CFDictionaryGetValue(d, key);
    if (!v) return -1;
    if (CFGetTypeID(v) == CFNumberGetTypeID()) {
        long long x = -1;
        CFNumberGetValue((CFNumberRef)v, kCFNumberLongLongType, &x);
        return (long)x;
    }
    if (CFGetTypeID(v) == CFBooleanGetTypeID()) {
        return CFBooleanGetValue((CFBooleanRef)v) ? 1 : 0;
    }
    return -1;
}

/* Force the image to be decoded into a bitmap and hash the pixels. */
static int draw_and_hash(CGImageRef img, unsigned long *hash, long *nz, long *pw, long *ph) {
    size_t w = CGImageGetWidth(img), h = CGImageGetHeight(img);
    if (w == 0 || h == 0 || w > 8192 || h > 8192) return -1;
    size_t stride = w * 4;
    unsigned char *buf = (unsigned char *)calloc(stride * h, 1);
    if (!buf) return -1;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(buf, w, h, 8, stride, cs,
                                             (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
    int ok = 0;
    if (ctx) {
        CGContextDrawImage(ctx, CGRectMake(0, 0, (CGFloat)w, (CGFloat)h), img);
        CGContextRelease(ctx);
        long z = 0;
        for (size_t i = 0; i < stride * h; i++) if (buf[i]) z++;
        *hash = fnv1a(buf, stride * h);
        *nz = z;
        *pw = (long)w;
        *ph = (long)h;
        ok = 1;
    }
    CGColorSpaceRelease(cs);
    free(buf);
    return ok ? 0 : -1;
}

static void one_file(const char *name, int idx) {
    char path[700];
    snprintf(path, sizeof path, "%s/%s", g_base, name);
    L("FILE %d %s", idx, name);

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (!url) { L("ERR url"); return; }
    CGImageSourceRef src = CGImageSourceCreateWithURL(url, NULL);
    CFRelease(url);
    if (!src) { L("ERR source"); return; }

    size_t count = CGImageSourceGetCount(src);
    char tbuf[128] = "?";
    CFStringRef type = CGImageSourceGetType(src);
    if (type) CFStringGetCString(type, tbuf, sizeof tbuf, kCFStringEncodingUTF8);

    CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(src, 0, NULL);
    long pw = prop_long(props, kCGImagePropertyPixelWidth);
    long ph = prop_long(props, kCGImagePropertyPixelHeight);
    long depth = prop_long(props, kCGImagePropertyDepth);
    long isfloat = prop_long(props, kCGImagePropertyIsFloat);
    long isidx = prop_long(props, kCGImagePropertyIsIndexed);
    L("PROPS count=%zu type=%s w=%ld h=%ld depth=%ld float=%ld indexed=%ld",
      count, tbuf, pw, ph, depth, isfloat, isidx);
    if (props) CFRelease(props);

    CGImageRef img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
    if (!img) {
        L("IMG null");
    } else {
        unsigned long hh = 0;
        long nz = 0, dw = 0, dh = 0;
        int rc = draw_and_hash(img, &hh, &nz, &dw, &dh);
        if (rc == 0) L("IMG ok %ldx%ld bpp=%zu bpc=%zu cs=%d hash=%lx nz=%ld",
                       dw, dh, CGImageGetBitsPerPixel(img),
                       CGImageGetBitsPerComponent(img),
                       CGImageGetColorSpace(img) != NULL, hh, nz);
        else         L("IMG draw-fail w=%zu h=%zu bpp=%zu",
                       CGImageGetWidth(img), CGImageGetHeight(img),
                       CGImageGetBitsPerPixel(img));
        CGImageRelease(img);
    }

    /* separate path: thumbnail (it has its own offset/length checks) */
    CFDictionaryRef thopts = (CFDictionaryRef)CFDictionaryCreate(
        NULL, NULL, NULL, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CGImageRef th = CGImageSourceCreateThumbnailAtIndex(src, 0, thopts);
    if (thopts) CFRelease(thopts);
    if (th) {
        L("THUMB ok %zux%zu", CGImageGetWidth(th), CGImageGetHeight(th));
        CGImageRelease(th);
    } else {
        L("THUMB null");
    }

    CFRelease(src);
}

int main(void) {
    const char *home = getenv("HOME");
    if (home && *home) snprintf(g_base, sizeof g_base, "%s/Documents", home);
    else snprintf(g_base, sizeof g_base, ".");

    char logpath[600];
    snprintf(logpath, sizeof logpath, "%s/probe.log", g_base);
    g = fopen(logpath, "a");
    if (!g) g = stderr;

    L("TIFF start pid=%d base=%s", (int)getpid(), g_base);

    /* cursor: how far the previous run got */
    char curpath[600];
    snprintf(curpath, sizeof curpath, "%s/cursor.txt", g_base);
    int start = 0;
    FILE *cf = fopen(curpath, "r");
    if (cf) {
        if (fscanf(cf, "%d", &start) != 1) start = 0;
        fclose(cf);
    }
    L("CURSOR start=%d", start);

    char listpath[600];
    snprintf(listpath, sizeof listpath, "%s/list.txt", g_base);
    FILE *lf = fopen(listpath, "r");
    if (!lf) { L("ERR no list.txt"); return 1; }

    char line[256];
    int idx = 0, done = 0;
    while (fgets(line, sizeof line, lf)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        if (!n) continue;
        if (idx < start) { idx++; continue; }
        /* write the cursor BEFORE decoding: a crash must not roll back progress */
        FILE *cw = fopen(curpath, "w");
        if (cw) { fprintf(cw, "%d\n", idx + 1); fclose(cw); }
        one_file(line, idx);
        idx++;
        done++;
    }
    fclose(lf);

    L("DONE processed=%d last_index=%d", done, idx);
    fclose(g);
    return 0;
}
