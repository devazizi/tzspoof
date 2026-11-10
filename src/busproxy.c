#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "busproxy.h"
#include "scrub.h"
#include "tzutil.h"
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>

/*
 * Scope and limits (deliberate):
 * - Only org.freedesktop.timedate1 is answered locally; everything else is
 *   relayed, including SCM_RIGHTS fds, so systemctl, nmcli, logind
 *   inhibitors etc. keep working.
 * - With --hostname, every string in messages from the real bus is checked
 *   for the real hostname(s) (hostnamed, NetworkManager, unit metadata...)
 *   and the message body is re-encoded with the spoofed name. Only
 *   little-endian bodies are rewritten (all x86/ARM peers use that).
 * - Writes are blocking. D-Bus peers always drain their sockets, and the
 *   traffic is small; a non-blocking write queue would only matter for a
 *   peer that stops reading, which would stall that one session's bus.
 * - Clients reaching timedated through its unique name obtained elsewhere
 *   (e.g. ListNames + GetConnection*) bypass the filter. GetNameOwner,
 *   NameHasOwner and StartServiceByName for timedate1 are answered locally
 *   so the usual client libraries (sd-bus, libdbus, GDBus) stay inside it.
 */

#define MAX_CONNS      128
#define MAX_MSG        (128u * 1024u * 1024u)
#define MAX_FDS_PER_IO 64
#define MAX_AUTH_LINE  16384

#define BUS_NAME       "org.freedesktop.DBus"
#define TD_NAME        "org.freedesktop.timedate1"
#define TD_PATH        "/org/freedesktop/timedate1"
#define TD_OWNER       ":1.4242424"
#define PROPS_IFACE    "org.freedesktop.DBus.Properties"
#define INTRO_IFACE    "org.freedesktop.DBus.Introspectable"
#define PEER_IFACE     "org.freedesktop.DBus.Peer"

enum { MSG_CALL = 1, MSG_RETURN = 2, MSG_ERROR = 3, MSG_SIGNAL = 4 };
enum { FLAG_NO_REPLY = 0x1 };

static int g_listen = -1;
static int g_upstream_path = -1;

/* ---------------------------------------------------------------- buffers */

typedef struct {
    uint8_t *d;
    size_t len, cap;
} buf_t;

static bool buf_put(buf_t *b, const void *p, size_t n) {
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (cap < b->len + n) cap *= 2;
        uint8_t *d = realloc(b->d, cap);
        if (!d) return false;
        b->d = d;
        b->cap = cap;
    }
    if (n) memcpy(b->d + b->len, p, n);
    b->len += n;
    return true;
}

static void buf_consume(buf_t *b, size_t n) {
    memmove(b->d, b->d + n, b->len - n);
    b->len -= n;
}

static void buf_free(buf_t *b) {
    free(b->d);
    memset(b, 0, sizeof(*b));
}

typedef struct {
    int fds[MAX_FDS_PER_IO * 4];
    int n;
} fdq_t;

static void fdq_push(fdq_t *q, int fd) {
    if (q->n < (int)(sizeof(q->fds) / sizeof(q->fds[0]))) q->fds[q->n++] = fd;
    else close(fd);
}

/* Take up to n fds from the front of the queue into out; returns count. */
static int fdq_take(fdq_t *q, int n, int *out) {
    if (n > q->n) n = q->n;
    memcpy(out, q->fds, (size_t)n * sizeof(int));
    memmove(q->fds, q->fds + n, (size_t)(q->n - n) * sizeof(int));
    q->n -= n;
    return n;
}

static void fdq_drop(fdq_t *q, int n) {
    int tmp[MAX_FDS_PER_IO * 4];
    int got = fdq_take(q, n, tmp);
    for (int i = 0; i < got; i++) close(tmp[i]);
}

/* ------------------------------------------------------- message parsing */

typedef struct {
    bool le;
    uint8_t type, flags;
    uint32_t serial, unix_fds, reply_serial;
    const char *path, *iface, *member, *dest, *sig;
    size_t body_off, body_len, total;
} hdr_t;

static uint32_t rd32(const uint8_t *p, bool le) {
    return le ? (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24
              : (uint32_t)p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 | (uint32_t)p[0] << 24;
}

static size_t align_up(size_t off, size_t a) { return (off + a - 1) & ~(a - 1); }

/* Total length of the message at p, 0 if incomplete, -1 if invalid. */
static long msg_length(const uint8_t *p, size_t avail) {
    if (avail < 16) return 0;
    if ((p[0] != 'l' && p[0] != 'B') || p[3] != 1) return -1;
    bool le = p[0] == 'l';
    uint64_t total = align_up(16 + (uint64_t)rd32(p + 12, le), 8) + rd32(p + 4, le);
    if (total > MAX_MSG) return -1;
    return avail >= total ? (long)total : 0;
}

/* Read a string at *off (D-Bus 's'/'o': 4-aligned length, bytes, NUL). */
static const char *rd_str(const uint8_t *m, size_t end, size_t *off, bool le) {
    size_t o = align_up(*off, 4);
    if (o + 4 > end) return NULL;
    uint32_t len = rd32(m + o, le);
    o += 4;
    if ((uint64_t)o + len >= end || m[o + len] != '\0') return NULL;
    *off = o + len + 1;
    return (const char *)m + o;
}

/* Read a signature at *off ('g': 1-byte length, bytes, NUL). */
static const char *rd_sig(const uint8_t *m, size_t end, size_t *off) {
    size_t o = *off;
    if (o >= end) return NULL;
    uint8_t len = m[o++];
    if (o + len >= end || m[o + len] != '\0') return NULL;
    *off = o + len + 1;
    return (const char *)m + o;
}

static bool parse_header(const uint8_t *m, size_t total, hdr_t *h) {
    memset(h, 0, sizeof(*h));
    h->le = m[0] == 'l';
    h->type = m[1];
    h->flags = m[2];
    h->serial = rd32(m + 8, h->le);
    h->total = total;
    size_t end = 16 + rd32(m + 12, h->le);
    h->body_off = align_up(end, 8);
    h->body_len = rd32(m + 4, h->le);
    if (end > total) return false;

    size_t off = 16;
    while (off < end) {
        off = align_up(off, 8);
        if (off >= end) break;
        uint8_t code = m[off++];
        const char *vsig = rd_sig(m, end, &off);
        if (!vsig || strlen(vsig) != 1) return false;
        const char *s = NULL;
        uint32_t u = 0;
        switch (vsig[0]) {
            case 's':
            case 'o':
                if (!(s = rd_str(m, end, &off, h->le))) return false;
                break;
            case 'g':
                if (!(s = rd_sig(m, end, &off))) return false;
                break;
            case 'u':
                off = align_up(off, 4);
                if (off + 4 > end) return false;
                u = rd32(m + off, h->le);
                off += 4;
                break;
            default:
                return false;
        }
        switch (code) {
            case 1: h->path = s; break;
            case 2: h->iface = s; break;
            case 3: h->member = s; break;
            case 6: h->dest = s; break;
            case 8: h->sig = s; break;
            case 5: h->reply_serial = u; break;
            case 9: h->unix_fds = u; break;
            default: break;
        }
    }
    return true;
}

/* First body argument as a string when the signature starts with 's'. */
static const char *body_arg_str(const uint8_t *m, const hdr_t *h, int index) {
    if (!h->sig) return NULL;
    size_t off = h->body_off, end = h->body_off + h->body_len;
    const char *s = NULL;
    for (int i = 0; i <= index; i++) {
        if (h->sig[i] != 's') return NULL;
        if (!(s = rd_str(m, end, &off, h->le))) return NULL;
    }
    return s;
}

static bool streq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

/* ------------------------------------------------------ message building */

typedef struct {
    buf_t b;
    size_t body_start;
} msg_t;

static void put_pad(buf_t *b, size_t a) {
    static const uint8_t zeros[8] = {0};
    buf_put(b, zeros, align_up(b->len, a) - b->len);
}

static void put_u8(buf_t *b, uint8_t v) { buf_put(b, &v, 1); }

static void put_u32(buf_t *b, uint32_t v) {
    put_pad(b, 4);
    uint8_t le[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    buf_put(b, le, 4);
}

static void put_u64(buf_t *b, uint64_t v) {
    put_pad(b, 8);
    uint8_t le[8];
    for (int i = 0; i < 8; i++) le[i] = (uint8_t)(v >> (8 * i));
    buf_put(b, le, 8);
}

static void patch_u32(buf_t *b, size_t at, uint32_t v) {
    uint8_t le[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    memcpy(b->d + at, le, 4);
}

static void put_str(buf_t *b, const char *s) {
    put_u32(b, (uint32_t)strlen(s));
    buf_put(b, s, strlen(s) + 1);
}

static void put_sig(buf_t *b, const char *s) {
    put_u8(b, (uint8_t)strlen(s));
    buf_put(b, s, strlen(s) + 1);
}

static void put_field(buf_t *b, uint8_t code, char type, const char *s, uint32_t u) {
    put_pad(b, 8);
    put_u8(b, code);
    char sig[2] = {type, 0};
    put_sig(b, sig);
    if (type == 'u') put_u32(b, u);
    else if (type == 'g') put_sig(b, s);
    else put_str(b, s);
}

static uint32_t g_serial = 1;

static void msg_begin(msg_t *m, uint8_t type, uint32_t reply_serial, const char *sender,
                      const char *dest, const char *error, const char *sig) {
    memset(m, 0, sizeof(*m));
    buf_t *b = &m->b;
    uint8_t fixed[4] = {'l', type, 0, 1};
    buf_put(b, fixed, 4);
    put_u32(b, 0);            /* body length, patched in msg_end */
    put_u32(b, g_serial++);
    put_u32(b, 0);            /* header field array length */
    size_t start = b->len;
    put_field(b, 5, 'u', NULL, reply_serial);
    put_field(b, 7, 's', sender, 0);
    if (dest) put_field(b, 6, 's', dest, 0);
    if (error) put_field(b, 4, 's', error, 0);
    if (sig && *sig) put_field(b, 8, 'g', sig, 0);
    patch_u32(b, 12, (uint32_t)(b->len - start));
    put_pad(b, 8);
    m->body_start = b->len;
}

static void msg_end(msg_t *m) { patch_u32(&m->b, 4, (uint32_t)(m->b.len - m->body_start)); }

static void msg_call(msg_t *m, const char *dest, const char *path, const char *iface,
                     const char *member, const char *sig) {
    memset(m, 0, sizeof(*m));
    buf_t *b = &m->b;
    uint8_t fixed[4] = {'l', MSG_CALL, 0, 1};
    buf_put(b, fixed, 4);
    put_u32(b, 0);
    put_u32(b, g_serial++);
    put_u32(b, 0);
    size_t start = b->len;
    put_field(b, 1, 'o', path, 0);
    put_field(b, 2, 's', iface, 0);
    put_field(b, 3, 's', member, 0);
    put_field(b, 6, 's', dest, 0);
    if (sig && *sig) put_field(b, 8, 'g', sig, 0);
    patch_u32(b, 12, (uint32_t)(b->len - start));
    put_pad(b, 8);
    m->body_start = b->len;
}

/* --------------------------------------------- hostname scrubbing (bodies) */

/* Length of one complete type at sig, 0 if invalid. */
static size_t sig_type_len(const char *sig) {
    switch (*sig) {
        case 'a': {
            size_t l = sig_type_len(sig + 1);
            return l ? l + 1 : 0;
        }
        case '(':
        case '{': {
            char close = *sig == '(' ? ')' : '}';
            size_t i = 1;
            while (sig[i] && sig[i] != close) {
                size_t l = sig_type_len(sig + i);
                if (!l) return 0;
                i += l;
            }
            return sig[i] == close ? i + 1 : 0;
        }
        case '\0':
            return 0;
        default:
            return strchr("ybnqiuxtdhsogv", *sig) ? 1 : 0;
    }
}

static size_t type_align(char c) {
    switch (c) {
        case 'y': case 'g': case 'v': return 1;
        case 'n': case 'q': return 2;
        case 'x': case 't': case 'd': case '(': case '{': return 8;
        default: return 4; /* b i u h s o a */
    }
}

typedef struct {
    const uint8_t *m;
    size_t off, end;
} reader_t;

static bool copy_raw(reader_t *r, buf_t *o, size_t n) {
    if (r->off + n > r->end) return false;
    buf_put(o, r->m + r->off, n);
    r->off += n;
    return true;
}

/* Copy one value of type sig (one complete type) from r to o, rewriting
 * strings that contain a real hostname. Offsets are absolute in the
 * message on both sides, so alignment is preserved. */
static bool copy_value(reader_t *r, const char *sig, buf_t *o, int depth) {
    if (depth > 64) return false;
    char c = sig[0];
    size_t a = type_align(c);
    r->off = align_up(r->off, a);
    put_pad(o, a);
    switch (c) {
        case 'y': return copy_raw(r, o, 1);
        case 'n': case 'q': return copy_raw(r, o, 2);
        case 'b': case 'i': case 'u': case 'h': return copy_raw(r, o, 4);
        case 'x': case 't': case 'd': return copy_raw(r, o, 8);
        case 's': case 'o': {
            if (r->off + 4 > r->end) return false;
            uint32_t len = rd32(r->m + r->off, true);
            if ((uint64_t)r->off + 4 + len + 1 > r->end) return false;
            const char *str = (const char *)r->m + r->off + 4;
            size_t new_len = 0;
            char *rep = c == 's' ? scrub_text(str, len, &new_len) : NULL;
            if (!rep) return copy_raw(r, o, 4 + (size_t)len + 1);
            put_u32(o, (uint32_t)new_len);
            buf_put(o, rep, new_len + 1);
            free(rep);
            r->off += 4 + (size_t)len + 1;
            return true;
        }
        case 'g': {
            if (r->off >= r->end) return false;
            return copy_raw(r, o, 1 + (size_t)r->m[r->off] + 1);
        }
        case 'v': {
            if (r->off >= r->end) return false;
            size_t sig_at = r->off + 1;
            if (!copy_raw(r, o, 1 + (size_t)r->m[r->off] + 1)) return false;
            const char *inner = (const char *)r->m + sig_at;
            if (sig_type_len(inner) != strlen(inner)) return false;
            return copy_value(r, inner, o, depth + 1);
        }
        case 'a': {
            if (r->off + 4 > r->end) return false;
            uint32_t len = rd32(r->m + r->off, true);
            r->off += 4;
            put_u32(o, 0);
            size_t len_at = o->len - 4;
            size_t ea = type_align(sig[1]);
            r->off = align_up(r->off, ea);
            put_pad(o, ea);
            size_t in_end = r->off + len, out_start = o->len;
            if (in_end > r->end) return false;
            while (r->off < in_end) {
                if (!copy_value(r, sig + 1, o, depth + 1)) return false;
            }
            if (r->off != in_end) return false;
            patch_u32(o, len_at, (uint32_t)(o->len - out_start));
            return true;
        }
        case '(': case '{': {
            const char *f = sig + 1;
            while (*f != ')' && *f != '}') {
                if (!copy_value(r, f, o, depth + 1)) return false;
                f += sig_type_len(f);
            }
            return true;
        }
        default:
            return false;
    }
}

/* Re-encode msg with real hostnames replaced. Returns a malloc'd buffer
 * (its length in *out_len) or NULL to forward the original unchanged. */
static uint8_t *scrub_message(const uint8_t *msg, const hdr_t *h, size_t *out_len) {
    if (!h->le || !h->sig || !*h->sig || scrub_count() == 0 ||
        !scrub_contains(msg + h->body_off, h->body_len)) {
        return NULL;
    }
    buf_t o = {0};
    buf_put(&o, msg, h->body_off); /* header unchanged; only its body length is patched */
    reader_t r = {.m = msg, .off = h->body_off, .end = h->body_off + h->body_len};
    for (const char *t = h->sig; *t; t += sig_type_len(t)) {
        if (!sig_type_len(t) || !copy_value(&r, t, &o, 0)) {
            buf_free(&o);
            return NULL; /* unexpected encoding: forward as-is rather than break it */
        }
    }
    patch_u32(&o, 4, (uint32_t)(o.len - h->body_off));
    *out_len = o.len;
    return o.d;
}

/* ------------------------------------------------------- timedate1 model */

static const char *g_zone;
static bool g_local_rtc;

static const char *const TD_PROPS[] = {
    "Timezone", "LocalRTC", "CanNTP", "NTP", "NTPSynchronized", "TimeUSec", "RTCTimeUSec", NULL
};

static const char INTROSPECT_XML[] =
    "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
    "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
    "<node>\n"
    " <interface name=\"org.freedesktop.timedate1\">\n"
    "  <property name=\"Timezone\" type=\"s\" access=\"read\"/>\n"
    "  <property name=\"LocalRTC\" type=\"b\" access=\"read\"/>\n"
    "  <property name=\"CanNTP\" type=\"b\" access=\"read\"/>\n"
    "  <property name=\"NTP\" type=\"b\" access=\"read\"/>\n"
    "  <property name=\"NTPSynchronized\" type=\"b\" access=\"read\"/>\n"
    "  <property name=\"TimeUSec\" type=\"t\" access=\"read\"/>\n"
    "  <property name=\"RTCTimeUSec\" type=\"t\" access=\"read\"/>\n"
    "  <method name=\"SetTime\"><arg type=\"x\" direction=\"in\"/><arg type=\"b\" direction=\"in\"/>"
    "<arg type=\"b\" direction=\"in\"/></method>\n"
    "  <method name=\"SetTimezone\"><arg type=\"s\" direction=\"in\"/><arg type=\"b\" direction=\"in\"/></method>\n"
    "  <method name=\"SetLocalRTC\"><arg type=\"b\" direction=\"in\"/><arg type=\"b\" direction=\"in\"/>"
    "<arg type=\"b\" direction=\"in\"/></method>\n"
    "  <method name=\"SetNTP\"><arg type=\"b\" direction=\"in\"/><arg type=\"b\" direction=\"in\"/></method>\n"
    "  <method name=\"ListTimezones\"><arg type=\"as\" direction=\"out\"/></method>\n"
    " </interface>\n"
    " <interface name=\"org.freedesktop.DBus.Properties\">\n"
    "  <method name=\"Get\"><arg type=\"s\" direction=\"in\"/><arg type=\"s\" direction=\"in\"/>"
    "<arg type=\"v\" direction=\"out\"/></method>\n"
    "  <method name=\"GetAll\"><arg type=\"s\" direction=\"in\"/><arg type=\"a{sv}\" direction=\"out\"/></method>\n"
    "  <method name=\"Set\"><arg type=\"s\" direction=\"in\"/><arg type=\"s\" direction=\"in\"/>"
    "<arg type=\"v\" direction=\"in\"/></method>\n"
    "  <signal name=\"PropertiesChanged\"><arg type=\"s\"/><arg type=\"a{sv}\"/><arg type=\"as\"/></signal>\n"
    " </interface>\n"
    " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
    "  <method name=\"Introspect\"><arg type=\"s\" direction=\"out\"/></method>\n"
    " </interface>\n"
    " <interface name=\"org.freedesktop.DBus.Peer\">\n"
    "  <method name=\"Ping\"/>\n"
    "  <method name=\"GetMachineId\"><arg type=\"s\" direction=\"out\"/></method>\n"
    " </interface>\n"
    "</node>\n";

static uint64_t now_usec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

/* Write property `name` as a variant; false if unknown. */
static bool put_prop_variant(buf_t *b, const char *name) {
    if (streq(name, "Timezone")) {
        put_sig(b, "s");
        put_str(b, g_zone);
    } else if (streq(name, "LocalRTC")) {
        put_sig(b, "b");
        put_u32(b, g_local_rtc);
    } else if (streq(name, "CanNTP") || streq(name, "NTP") || streq(name, "NTPSynchronized")) {
        put_sig(b, "b");
        put_u32(b, 1);
    } else if (streq(name, "TimeUSec") || streq(name, "RTCTimeUSec")) {
        put_sig(b, "t");
        put_u64(b, now_usec());
    } else {
        return false;
    }
    return true;
}

static void read_local_rtc(void) {
    /* /etc/adjtime line 3 is "UTC" or "LOCAL". */
    FILE *fp = fopen("/etc/adjtime", "r");
    if (!fp) return;
    char line[64];
    for (int i = 0; i < 3 && fgets(line, sizeof(line), fp); i++) {
        if (i == 2) g_local_rtc = strncmp(line, "LOCAL", 5) == 0;
    }
    fclose(fp);
}

/* ------------------------------------------------------------ connections */

typedef struct {
    int cfd, ufd;
    bool nul_seen, client_began, upstream_msgs;
    int pending_server_lines;
    buf_t cin, uin;
    fdq_t cq, uq;
    char unique[256]; /* client's unique name, learned from upstream traffic */
} conn_t;

static conn_t *g_conns[MAX_CONNS];

static bool send_all(int fd, const uint8_t *d, size_t len, const int *fds, int nfds) {
    size_t sent = 0;
    while (sent < len) {
        struct iovec iov = {.iov_base = (void *)(d + sent), .iov_len = len - sent};
        struct msghdr mh = {.msg_iov = &iov, .msg_iovlen = 1};
        union {
            char buf[CMSG_SPACE(sizeof(int) * MAX_FDS_PER_IO * 4)];
            struct cmsghdr align;
        } ctl;
        if (sent == 0 && nfds > 0) {
            mh.msg_control = ctl.buf;
            mh.msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)nfds);
            struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
            c->cmsg_level = SOL_SOCKET;
            c->cmsg_type = SCM_RIGHTS;
            c->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)nfds);
            memcpy(CMSG_DATA(c), fds, sizeof(int) * (size_t)nfds);
        }
        ssize_t n = sendmsg(fd, &mh, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        sent += (size_t)n;
    }
    return true;
}

static bool forward(int to, const uint8_t *d, size_t len, fdq_t *q, uint32_t nfds) {
    int fds[MAX_FDS_PER_IO * 4];
    int n = fdq_take(q, (int)nfds, fds);
    bool ok = send_all(to, d, len, fds, n);
    for (int i = 0; i < n; i++) close(fds[i]); /* the receiver has its own copies now */
    return ok;
}

static bool reply(conn_t *c, msg_t *m) {
    msg_end(m);
    bool ok = send_all(c->cfd, m->b.d, m->b.len, NULL, 0);
    buf_free(&m->b);
    return ok;
}

static const char *dest_of(conn_t *c) { return c->unique[0] ? c->unique : NULL; }

static bool reply_error(conn_t *c, const hdr_t *h, const char *sender, const char *name, const char *text) {
    if (h->flags & FLAG_NO_REPLY) return true;
    msg_t m;
    msg_begin(&m, MSG_ERROR, h->serial, sender, dest_of(c), name, "s");
    put_str(&m.b, text);
    return reply(c, &m);
}

/* Answer a method call addressed to timedate1. */
static bool handle_timedate(conn_t *c, const uint8_t *msg, const hdr_t *h) {
    const char *iface = h->iface ? h->iface : "";
    const char *member = h->member ? h->member : "";
    bool no_reply = h->flags & FLAG_NO_REPLY;
    msg_t m;

    if (streq(iface, PROPS_IFACE) || (!*iface && (streq(member, "Get") || streq(member, "GetAll")))) {
        const char *want_iface = body_arg_str(msg, h, 0);
        if (want_iface && *want_iface && !streq(want_iface, TD_NAME)) {
            return reply_error(c, h, TD_OWNER, "org.freedesktop.DBus.Error.UnknownInterface",
                               "Unknown interface");
        }
        if (streq(member, "Get")) {
            const char *prop = body_arg_str(msg, h, 1);
            if (no_reply) return true;
            msg_begin(&m, MSG_RETURN, h->serial, TD_OWNER, dest_of(c), NULL, "v");
            if (!prop || !put_prop_variant(&m.b, prop)) {
                buf_free(&m.b);
                return reply_error(c, h, TD_OWNER, "org.freedesktop.DBus.Error.UnknownProperty",
                                   "Unknown property");
            }
            return reply(c, &m);
        }
        if (streq(member, "GetAll")) {
            if (no_reply) return true;
            msg_begin(&m, MSG_RETURN, h->serial, TD_OWNER, dest_of(c), NULL, "a{sv}");
            put_u32(&m.b, 0);
            size_t len_at = m.b.len - 4;
            put_pad(&m.b, 8);
            size_t start = m.b.len;
            for (int i = 0; TD_PROPS[i]; i++) {
                put_pad(&m.b, 8);
                put_str(&m.b, TD_PROPS[i]);
                put_prop_variant(&m.b, TD_PROPS[i]);
            }
            patch_u32(&m.b, len_at, (uint32_t)(m.b.len - start));
            return reply(c, &m);
        }
        if (streq(member, "Set")) {
            return reply_error(c, h, TD_OWNER, "org.freedesktop.DBus.Error.PropertyReadOnly",
                               "Property is read-only");
        }
    } else if (streq(iface, INTRO_IFACE) || (!*iface && streq(member, "Introspect"))) {
        if (no_reply) return true;
        msg_begin(&m, MSG_RETURN, h->serial, TD_OWNER, dest_of(c), NULL, "s");
        put_str(&m.b, INTROSPECT_XML);
        return reply(c, &m);
    } else if (streq(iface, PEER_IFACE) || (!*iface && (streq(member, "Ping") || streq(member, "GetMachineId")))) {
        if (streq(member, "Ping")) {
            if (no_reply) return true;
            msg_begin(&m, MSG_RETURN, h->serial, TD_OWNER, dest_of(c), NULL, NULL);
            return reply(c, &m);
        }
        if (streq(member, "GetMachineId")) {
            char id[64] = {0};
            FILE *fp = fopen("/etc/machine-id", "r");
            if (fp) {
                if (!fgets(id, sizeof(id), fp)) id[0] = '\0';
                fclose(fp);
            }
            id[strcspn(id, "\n")] = '\0';
            if (no_reply) return true;
            msg_begin(&m, MSG_RETURN, h->serial, TD_OWNER, dest_of(c), NULL, "s");
            put_str(&m.b, id);
            return reply(c, &m);
        }
    } else if (streq(iface, TD_NAME) || !*iface) {
        if (streq(member, "ListTimezones")) {
            if (no_reply) return true;
            char **zones = NULL;
            size_t n = tz_collect(&zones);
            msg_begin(&m, MSG_RETURN, h->serial, TD_OWNER, dest_of(c), NULL, "as");
            put_u32(&m.b, 0);
            size_t len_at = m.b.len - 4, start = m.b.len;
            for (size_t i = 0; i < n; i++) put_str(&m.b, zones[i]);
            patch_u32(&m.b, len_at, (uint32_t)(m.b.len - start));
            tz_collect_free(zones, n);
            return reply(c, &m);
        }
        if (streq(member, "SetTime") || streq(member, "SetTimezone") || streq(member, "SetLocalRTC") ||
            streq(member, "SetNTP")) {
            return reply_error(c, h, TD_OWNER, "org.freedesktop.DBus.Error.AccessDenied",
                               "Changing time settings is not permitted in this tzspoof session");
        }
    }
    return reply_error(c, h, TD_OWNER, "org.freedesktop.DBus.Error.UnknownMethod", "Unknown method");
}

/* Bus-driver queries about timedate1's owner are answered locally so that
 * clients keep addressing it through the filter. Returns true if handled. */
static bool handle_driver(conn_t *c, const uint8_t *msg, const hdr_t *h, bool *ok) {
    if (!streq(h->dest, BUS_NAME) || !streq(body_arg_str(msg, h, 0), TD_NAME)) return false;
    const char *sig;
    if (streq(h->member, "GetNameOwner")) sig = "s";
    else if (streq(h->member, "NameHasOwner")) sig = "b";
    else if (streq(h->member, "StartServiceByName")) sig = "u";
    else return false;

    *ok = true;
    if (h->flags & FLAG_NO_REPLY) return true;
    msg_t m;
    msg_begin(&m, MSG_RETURN, h->serial, BUS_NAME, dest_of(c), NULL, sig);
    if (sig[0] == 's') put_str(&m.b, TD_OWNER);
    else if (sig[0] == 'b') put_u32(&m.b, 1);
    else put_u32(&m.b, 2); /* DBUS_START_REPLY_ALREADY_RUNNING */
    *ok = reply(c, &m);
    return true;
}

/* Process complete messages from the client. */
static bool client_messages(conn_t *c) {
    long total;
    while ((total = msg_length(c->cin.d, c->cin.len)) > 0) {
        hdr_t h;
        bool parsed = parse_header(c->cin.d, (size_t)total, &h);
        bool ok = true;
        if (parsed && h.type == MSG_CALL && (streq(h.dest, TD_NAME) || streq(h.dest, TD_OWNER))) {
            ok = handle_timedate(c, c->cin.d, &h);
            fdq_drop(&c->cq, (int)h.unix_fds);
        } else if (parsed && h.type == MSG_CALL && handle_driver(c, c->cin.d, &h, &ok)) {
            fdq_drop(&c->cq, (int)h.unix_fds);
        } else {
            ok = forward(c->ufd, c->cin.d, (size_t)total, &c->cq, parsed ? h.unix_fds : 0);
        }
        buf_consume(&c->cin, (size_t)total);
        if (!ok) return false;
    }
    return total == 0;
}

/* Process complete messages from the real bus. */
static bool upstream_messages(conn_t *c) {
    long total;
    while ((total = msg_length(c->uin.d, c->uin.len)) > 0) {
        hdr_t h;
        bool parsed = parse_header(c->uin.d, (size_t)total, &h);
        bool ok = true;
        if (parsed && h.dest && h.dest[0] == ':' && !c->unique[0]) {
            snprintf(c->unique, sizeof(c->unique), "%s", h.dest);
        }
        uint8_t *scrubbed = NULL;
        size_t scrubbed_len = 0;
        if (parsed && h.type == MSG_SIGNAL && streq(h.path, TD_PATH)) {
            fdq_drop(&c->uq, (int)h.unix_fds); /* real timedated's PropertiesChanged */
        } else if (parsed && (scrubbed = scrub_message(c->uin.d, &h, &scrubbed_len))) {
            ok = forward(c->cfd, scrubbed, scrubbed_len, &c->uq, h.unix_fds);
            free(scrubbed);
        } else {
            ok = forward(c->cfd, c->uin.d, (size_t)total, &c->uq, parsed ? h.unix_fds : 0);
        }
        buf_consume(&c->uin, (size_t)total);
        if (!ok) return false;
    }
    return total == 0;
}

/* SASL phase, client side: relay lines, count those the server answers. */
static bool client_auth(conn_t *c) {
    if (!c->nul_seen && c->cin.len > 0) {
        if (!send_all(c->ufd, c->cin.d, 1, NULL, 0)) return false;
        buf_consume(&c->cin, 1);
        c->nul_seen = true;
    }
    while (!c->client_began) {
        uint8_t *eol = memmem(c->cin.d, c->cin.len, "\r\n", 2);
        if (!eol) return c->cin.len < MAX_AUTH_LINE;
        size_t n = (size_t)(eol - c->cin.d) + 2;
        if (!send_all(c->ufd, c->cin.d, n, NULL, 0)) return false;
        if (n >= 7 && memcmp(c->cin.d, "BEGIN\r\n", 7) == 0) c->client_began = true;
        else c->pending_server_lines++;
        buf_consume(&c->cin, n);
    }
    return true;
}

/* SASL phase, server side: relay the answers to the client's lines. */
static bool upstream_auth(conn_t *c) {
    while (!c->upstream_msgs) {
        if (c->client_began && c->pending_server_lines <= 0) {
            c->upstream_msgs = true;
            break;
        }
        uint8_t *eol = memmem(c->uin.d, c->uin.len, "\r\n", 2);
        if (!eol) return c->uin.len < MAX_AUTH_LINE;
        size_t n = (size_t)(eol - c->uin.d) + 2;
        if (!send_all(c->cfd, c->uin.d, n, NULL, 0)) return false;
        buf_consume(&c->uin, n);
        c->pending_server_lines--;
    }
    return true;
}

/* Read from fd into b, queueing received fds. False on EOF/error. */
static bool read_into(int fd, buf_t *b, fdq_t *q) {
    uint8_t data[65536];
    union {
        char buf[CMSG_SPACE(sizeof(int) * MAX_FDS_PER_IO)];
        struct cmsghdr align;
    } ctl;
    struct iovec iov = {.iov_base = data, .iov_len = sizeof(data)};
    struct msghdr mh = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctl.buf, .msg_controllen = sizeof(ctl.buf)};
    ssize_t n;
    do {
        n = recvmsg(fd, &mh, MSG_CMSG_CLOEXEC);
    } while (n < 0 && errno == EINTR);
    if (n <= 0) return false;
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
            int cnt = (int)((cm->cmsg_len - CMSG_LEN(0)) / sizeof(int));
            int *fds = (int *)CMSG_DATA(cm);
            for (int i = 0; i < cnt; i++) fdq_push(q, fds[i]);
        }
    }
    return buf_put(b, data, (size_t)n);
}

static void conn_close(int i) {
    conn_t *c = g_conns[i];
    close(c->cfd);
    close(c->ufd);
    fdq_drop(&c->cq, c->cq.n);
    fdq_drop(&c->uq, c->uq.n);
    buf_free(&c->cin);
    buf_free(&c->uin);
    free(c);
    g_conns[i] = NULL;
}

static int connect_upstream(int path_fd) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    snprintf(sa.sun_path, sizeof(sa.sun_path), "/proc/self/fd/%d", path_fd);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void accept_client(int listen_fd, int path_fd) {
    int cfd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
    if (cfd < 0) return;
    int slot = -1;
    for (int i = 0; i < MAX_CONNS && slot < 0; i++) {
        if (!g_conns[i]) slot = i;
    }
    int ufd = slot >= 0 ? connect_upstream(path_fd) : -1;
    conn_t *c = ufd >= 0 ? calloc(1, sizeof(*c)) : NULL;
    if (!c) {
        if (ufd >= 0) close(ufd);
        close(cfd);
        return;
    }
    c->cfd = cfd;
    c->ufd = ufd;
    g_conns[slot] = c;
}

void busproxy_serve(int listen_fd, int path_fd, const char *tz_canonical) {
    g_zone = tz_canonical;
    read_local_rtc();
    struct pollfd pfd[1 + 2 * MAX_CONNS];
    int owner[1 + 2 * MAX_CONNS];

    for (;;) {
        int n = 0;
        pfd[n] = (struct pollfd){.fd = listen_fd, .events = POLLIN};
        owner[n++] = -1;
        for (int i = 0; i < MAX_CONNS; i++) {
            if (!g_conns[i]) continue;
            pfd[n] = (struct pollfd){.fd = g_conns[i]->cfd, .events = POLLIN};
            owner[n++] = i;
            pfd[n] = (struct pollfd){.fd = g_conns[i]->ufd, .events = POLLIN};
            owner[n++] = i;
        }
        if (poll(pfd, (nfds_t)n, -1) < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if (pfd[0].revents & POLLIN) accept_client(listen_fd, path_fd);
        for (int k = 1; k < n; k++) {
            int i = owner[k];
            conn_t *c = g_conns[i];
            if (!c || !(pfd[k].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            bool ok;
            if (pfd[k].fd == c->cfd) {
                ok = read_into(c->cfd, &c->cin, &c->cq);
                if (ok && !c->client_began) ok = client_auth(c);
                if (ok && c->client_began) ok = client_messages(c);
                /* BEGIN may complete the upstream side's auth phase. */
                if (ok && !c->upstream_msgs) ok = upstream_auth(c);
                if (ok && c->upstream_msgs) ok = upstream_messages(c);
            } else {
                ok = read_into(c->ufd, &c->uin, &c->uq);
                if (ok && !c->upstream_msgs) ok = upstream_auth(c);
                if (ok && c->upstream_msgs) ok = upstream_messages(c);
            }
            if (!ok) conn_close(i);
        }
    }
}

bool busproxy_prepare(int scratch_dir_fd) {
    struct stat st;
    if (lstat(SYSTEM_BUS_SOCKET, &st) != 0 || !S_ISSOCK(st.st_mode)) return false;

    int path_fd = open(SYSTEM_BUS_SOCKET, O_PATH | O_CLOEXEC);
    if (path_fd < 0) return false;

    int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    snprintf(sa.sun_path, sizeof(sa.sun_path), "/proc/self/fd/%d/%s", scratch_dir_fd, BUSPROXY_SOCKET_NAME);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        fchmodat(scratch_dir_fd, BUSPROXY_SOCKET_NAME, 0666, 0) != 0 || listen(lfd, 64) != 0) {
        int saved = errno;
        if (lfd >= 0) close(lfd);
        close(path_fd);
        errno = saved;
        return false;
    }
    g_listen = lfd;
    g_upstream_path = path_fd;
    return true;
}

void busproxy_cancel(void) {
    if (g_listen >= 0) close(g_listen);
    if (g_upstream_path >= 0) close(g_upstream_path);
    g_listen = g_upstream_path = -1;
}

void busproxy_start(const char *tz_canonical) {
    if (g_listen < 0) return;
    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid == 0) {
        /* Die with the command (this process's parent after exec). */
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != parent) _exit(0);
        setsid(); /* no controlling terminal: Ctrl+C/Ctrl+Z do not reach the proxy */
        signal(SIGPIPE, SIG_IGN);
        int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
        }
        busproxy_serve(g_listen, g_upstream_path, tz_canonical);
        _exit(0);
    }
    /* Parent (and failed fork): the command never needs these fds. */
    busproxy_cancel();
}

/* Read whole messages from fd into b until one replies to `serial`. */
static bool wait_reply(int fd, buf_t *b, uint32_t serial, hdr_t *h, long *total) {
    for (;;) {
        long t;
        while ((t = msg_length(b->d, b->len)) > 0) {
            if (parse_header(b->d, (size_t)t, h) && h->reply_serial == serial &&
                (h->type == MSG_RETURN || h->type == MSG_ERROR)) {
                *total = t;
                return true;
            }
            buf_consume(b, (size_t)t);
        }
        if (t < 0) return false;
        struct pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, 2000) <= 0) return false;
        uint8_t data[16384];
        ssize_t n = read(fd, data, sizeof(data));
        if (n <= 0 || !buf_put(b, data, (size_t)n)) return false;
    }
}

int busproxy_query_hostnames(void (*add)(const char *name)) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", SYSTEM_BUS_SOCKET);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        if (fd >= 0) close(fd);
        return 0;
    }
    char uid[16], auth[64] = "";
    snprintf(uid, sizeof(uid), "%u", (unsigned)getuid());
    size_t al = (size_t)snprintf(auth, sizeof(auth), "%cAUTH EXTERNAL ", '\0');
    for (const char *p = uid; *p; p++) al += (size_t)snprintf(auth + al, sizeof(auth) - al, "%02x", *p);
    al += (size_t)snprintf(auth + al, sizeof(auth) - al, "\r\n");

    int found = 0;
    buf_t in = {0};
    char line[256];
    ssize_t n;
    struct pollfd p = {.fd = fd, .events = POLLIN};
    if (!send_all(fd, (const uint8_t *)auth, al, NULL, 0) || poll(&p, 1, 2000) <= 0 ||
        (n = read(fd, line, sizeof(line) - 1)) <= 2 || strncmp(line, "OK ", 3) != 0 ||
        !send_all(fd, (const uint8_t *)"BEGIN\r\n", 7, NULL, 0)) {
        close(fd);
        return 0;
    }

    msg_t m;
    msg_call(&m, BUS_NAME, "/org/freedesktop/DBus", BUS_NAME, "Hello", NULL);
    msg_end(&m);
    uint32_t hello = rd32(m.b.d + 8, true);
    bool ok = send_all(fd, m.b.d, m.b.len, NULL, 0);
    buf_free(&m.b);
    hdr_t h;
    long total;
    ok = ok && wait_reply(fd, &in, hello, &h, &total);
    if (ok) buf_consume(&in, (size_t)total);

    static const char *const props[] = {"StaticHostname", "Hostname", "PrettyHostname"};
    for (size_t i = 0; ok && i < sizeof(props) / sizeof(props[0]); i++) {
        msg_call(&m, "org.freedesktop.hostname1", "/org/freedesktop/hostname1", PROPS_IFACE, "Get", "ss");
        put_str(&m.b, "org.freedesktop.hostname1");
        put_str(&m.b, props[i]);
        msg_end(&m);
        uint32_t serial = rd32(m.b.d + 8, true);
        ok = send_all(fd, m.b.d, m.b.len, NULL, 0) && wait_reply(fd, &in, serial, &h, &total);
        buf_free(&m.b);
        if (!ok) break;
        if (h.type == MSG_RETURN && h.le && streq(h.sig, "v")) {
            size_t off = h.body_off, end = h.body_off + h.body_len;
            const char *vs = rd_sig(in.d, end, &off);
            const char *val = streq(vs, "s") ? rd_str(in.d, end, &off, true) : NULL;
            if (val && *val) {
                add(val);
                found++;
            }
        }
        buf_consume(&in, (size_t)total);
    }
    buf_free(&in);
    close(fd);
    return found;
}
