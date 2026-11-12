#include "logforge.h"

#define IP_CAP (1u << 17)
#define IP_MAX_LOAD 90000u
#define IP_KEY 46
#define PATH_CAP (1u << 16)
#define PATH_MAX_LOAD 45000u
#define PATH_KEY 96
#define DEC_MAX 2047
#define UA_MAX 511
#define TOP_N 5
#define BRUTE_MIN 10u

typedef struct { char key[IP_KEY]; uint8_t klen; uint32_t count, attacks, authfail; } ip_slot;
typedef struct { char key[PATH_KEY]; uint8_t klen; uint32_t count; } path_slot;

struct lf_ctx {
    uint64_t lines, parsed, malformed, bytes;
    uint64_t status[5]; /* 1xx .. 5xx */
    uint64_t rules[LF_RULES];
    uint64_t attack_lines;
    int64_t first_ts, last_ts;
    int have_ts;
    uint64_t unique_ips, ip_overflow, unique_paths, path_overflow;
    size_t carry_len;
    int discarding;
    char carry[LF_MAX_LINE];
    ip_slot ips[IP_CAP];
    path_slot paths[PATH_CAP];
};

size_t lf_ctx_size(void) { return sizeof(struct lf_ctx); }

void lf_init(lf_ctx *c) {
    unsigned char *p = (unsigned char *)c;
    for (size_t i = 0; i < sizeof *c; i++) p[i] = 0;
}

/* ------------------------------------------------------------------ small helpers */

static size_t cstrlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

static int hexval(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static char lower(char ch) { return (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch; }

/* ------------------------------------------------------------------ parsing */

static int is_leap(int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

static int64_t days_from_civil(int64_t y, int m, int d) {
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static int digits(const char *p, int n) {
    int v = 0;
    for (int i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') return -1;
        v = v * 10 + (p[i] - '0');
    }
    return v;
}

/* "10/Oct/2026:13:55:36 +0000" (exactly 26 bytes) */
static int parse_time(const char *s, size_t n, int64_t *out) {
    static const char *mon = "JanFebMarAprMayJunJulAugSepOctNovDec";
    if (n != 26 || s[2] != '/' || s[6] != '/' || s[11] != ':' || s[14] != ':' || s[17] != ':' || s[20] != ' ') return 0;
    int d = digits(s, 2), y = digits(s + 7, 4), hh = digits(s + 12, 2), mm = digits(s + 15, 2), ss = digits(s + 18, 2);
    int th = digits(s + 22, 2), tm = digits(s + 24, 2);
    if (d < 1 || y < 1970 || y > 2100 || hh < 0 || hh > 23 || mm < 0 || mm > 59 || ss < 0 || ss > 60 || th < 0 || th > 23 || tm < 0 || tm > 59) return 0;
    if (s[21] != '+' && s[21] != '-') return 0;
    int m = 0;
    for (int i = 0; i < 12; i++)
        if (s[3] == mon[i * 3] && s[4] == mon[i * 3 + 1] && s[5] == mon[i * 3 + 2]) m = i + 1;
    if (!m) return 0;
    static const int dim[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int maxd = dim[m - 1] + (m == 2 && is_leap(y));
    if (d > maxd) return 0;
    int64_t t = days_from_civil(y, m, d) * 86400 + hh * 3600 + mm * 60 + ss;
    int64_t off = th * 3600 + tm * 60;
    *out = s[21] == '+' ? t - off : t + off;
    return 1;
}

/* Finds the closing quote starting at p (just after the opening one). A backslash escapes
 * the next byte. Returns the index of the quote or -1. */
static long find_quote(const char *s, size_t n, size_t p) {
    while (p < n) {
        if (s[p] == '\\') { p += 2; continue; }
        if (s[p] == '"') return (long)p;
        p++;
    }
    return -1;
}

static size_t token_end(const char *s, size_t n, size_t p) {
    while (p < n && s[p] != ' ') p++;
    return p;
}

int lf_parse_line(const char *s, size_t n, lf_entry *e) {
    size_t p = 0, q;
    /* client address */
    q = token_end(s, n, p);
    if (q == p || q - p > 45) return 0;
    for (size_t i = p; i < q; i++)
        if (hexval(s[i]) < 0 && s[i] != ':' && s[i] != '.') return 0;
    e->ip = s + p; e->ip_len = q - p;
    p = q;
    /* ident and user */
    for (int k = 0; k < 2; k++) {
        if (p >= n || s[p] != ' ') return 0;
        p++;
        q = token_end(s, n, p);
        if (q == p) return 0;
        p = q;
    }
    if (p + 2 > n || s[p] != ' ' || s[p + 1] != '[') return 0;
    p += 2;
    q = p;
    while (q < n && s[q] != ']') q++;
    if (q >= n || !parse_time(s + p, q - p, &e->ts)) return 0;
    p = q + 1;
    if (p + 2 > n || s[p] != ' ' || s[p + 1] != '"') return 0;
    p += 2;
    long cq = find_quote(s, n, p);
    if (cq < 0) return 0;
    const char *req = s + p;
    size_t rlen = (size_t)cq - p;
    p = (size_t)cq + 1;
    /* status and bytes */
    if (p + 5 > n || s[p] != ' ') return 0;
    int st = digits(s + p + 1, 3);
    if (st < 100 || st > 599 || s[p + 4] != ' ') return 0;
    e->status = st;
    p += 5;
    q = token_end(s, n, p);
    if (q == p) return 0;
    if (q - p == 1 && s[p] == '-') {
        e->bytes = 0;
    } else {
        if (q - p > 18) return 0;
        uint64_t b = 0;
        for (size_t i = p; i < q; i++) {
            if (s[i] < '0' || s[i] > '9') return 0;
            b = b * 10 + (uint64_t)(s[i] - '0');
        }
        e->bytes = b;
    }
    p = q;
    /* optional referer and user agent */
    e->ref = s; e->ref_len = 0; e->ua = s; e->ua_len = 0;
    if (p < n) {
        if (p + 2 > n || s[p] != ' ' || s[p + 1] != '"') return 0;
        p += 2;
        cq = find_quote(s, n, p);
        if (cq < 0) return 0;
        e->ref = s + p; e->ref_len = (size_t)cq - p;
        p = (size_t)cq + 1;
        if (p + 2 > n || s[p] != ' ' || s[p + 1] != '"') return 0;
        p += 2;
        cq = find_quote(s, n, p);
        if (cq < 0) return 0;
        e->ua = s + p; e->ua_len = (size_t)cq - p;
        p = (size_t)cq + 1;
        if (p != n) return 0;
    }
    /* request line: METHOD SP TARGET [SP PROTO] */
    size_t m = 0;
    while (m < rlen && req[m] != ' ') m++;
    e->method = req; e->method_len = m;
    size_t t0 = m < rlen ? m + 1 : rlen, t1 = t0;
    while (t1 < rlen && req[t1] != ' ') t1++;
    e->path = req + t0; e->path_len = t1 - t0;
    return 1;
}

/* ------------------------------------------------------------------ detection */

static int contains(const char *h, size_t hn, const char *needle) {
    size_t nn = cstrlen(needle);
    if (nn == 0 || hn < nn) return 0;
    for (size_t i = 0; i + nn <= hn; i++) {
        size_t k = 0;
        while (k < nn && h[i + k] == needle[k]) k++;
        if (k == nn) return 1;
    }
    return 0;
}

static int contains_any(const char *h, size_t hn, const char *const *list) {
    for (; *list; list++)
        if (contains(h, hn, *list)) return 1;
    return 0;
}

/* URL-decode and lowercase into dst (cap DEC_MAX). '+' becomes a space. */
static size_t decode_lower(const char *s, size_t n, char *dst) {
    size_t o = 0;
    for (size_t i = 0; i < n && o < DEC_MAX; i++) {
        char ch = s[i];
        if (ch == '%' && i + 2 < n) {
            int a = hexval(s[i + 1]), b = hexval(s[i + 2]);
            if (a >= 0 && b >= 0) { dst[o++] = lower((char)(a * 16 + b)); i += 2; continue; }
        }
        dst[o++] = ch == '+' ? ' ' : lower(ch);
    }
    return o;
}

static size_t copy_lower(const char *s, size_t n, char *dst) {
    size_t o = n > UA_MAX ? UA_MAX : n;
    for (size_t i = 0; i < o; i++) dst[i] = lower(s[i]);
    return o;
}

static const char *const SQLI[] = {"union select", "or 1=1", "' or '", "sleep(", "information_schema", "benchmark(", "; drop ", 0};
static const char *const TRAV[] = {"../", "..\\", "/etc/passwd", "boot.ini", 0};
static const char *const XSS[] = {"<script", "onerror=", "onload=", "javascript:", "<svg", 0};
static const char *const SCAN[] = {"sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "wpscan", "nuclei", "zgrab", 0};
static const char *const SENS[] = {".env", ".git/", "wp-config", ".aws/credentials", "id_rsa", "phpinfo", ".htpasswd", "/server-status", 0};

unsigned lf_detect(const lf_entry *e) {
    char dec[DEC_MAX], ua[UA_MAX], ref[UA_MAX];
    size_t dn = decode_lower(e->path, e->path_len, dec);
    size_t un = copy_lower(e->ua, e->ua_len, ua);
    size_t rn = copy_lower(e->ref, e->ref_len, ref);
    unsigned m = 0;
    if (contains_any(dec, dn, SQLI)) m |= 1u << LF_SQLI;
    if (contains_any(dec, dn, TRAV)) m |= 1u << LF_TRAVERSAL;
    if (contains_any(dec, dn, XSS)) m |= 1u << LF_XSS;
    if (contains_any(ua, un, SCAN)) m |= 1u << LF_SCANNER;
    if (contains(dec, dn, "() {") || contains(ua, un, "() {") || contains(ref, rn, "() {")) m |= 1u << LF_SHELLSHOCK;
    if (contains(dec, dn, "${jndi:") || contains(ua, un, "${jndi:") || contains(ref, rn, "${jndi:")) m |= 1u << LF_LOG4SHELL;
    size_t pn = 0;
    while (pn < dn && dec[pn] != '?') pn++;
    if (contains_any(dec, pn, SENS)) m |= 1u << LF_SENSITIVE;
    return m;
}

/* ------------------------------------------------------------------ aggregation */

static uint64_t fnv(const char *s, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) { h ^= (unsigned char)s[i]; h *= 1099511628211ull; }
    return h;
}

static int keq(const char *a, size_t an, const char *b, size_t bn) {
    if (an != bn) return 0;
    for (size_t i = 0; i < an; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static ip_slot *ip_get(lf_ctx *c, const char *k, size_t n) {
    uint32_t i = (uint32_t)(fnv(k, n) & (IP_CAP - 1));
    for (;;) {
        ip_slot *s = &c->ips[i];
        if (s->klen == 0) {
            if (c->unique_ips >= IP_MAX_LOAD) { c->ip_overflow++; return 0; }
            for (size_t j = 0; j < n; j++) s->key[j] = k[j];
            s->klen = (uint8_t)n;
            c->unique_ips++;
            return s;
        }
        if (keq(s->key, s->klen, k, n)) return s;
        i = (i + 1) & (IP_CAP - 1);
    }
}

static path_slot *path_get(lf_ctx *c, const char *k, size_t n) {
    uint32_t i = (uint32_t)(fnv(k, n) & (PATH_CAP - 1));
    for (;;) {
        path_slot *s = &c->paths[i];
        if (s->klen == 0) {
            if (c->unique_paths >= PATH_MAX_LOAD) { c->path_overflow++; return 0; }
            for (size_t j = 0; j < n; j++) s->key[j] = k[j];
            s->klen = (uint8_t)n;
            c->unique_paths++;
            return s;
        }
        if (keq(s->key, s->klen, k, n)) return s;
        i = (i + 1) & (PATH_CAP - 1);
    }
}

static void handle_line(lf_ctx *c, const char *s, size_t n) {
    if (n && s[n - 1] == '\r') n--;
    if (n == 0) return;
    c->lines++;
    lf_entry e;
    if (!lf_parse_line(s, n, &e)) { c->malformed++; return; }
    c->parsed++;
    c->bytes += e.bytes;
    c->status[e.status / 100 - 1]++;
    if (!c->have_ts || e.ts < c->first_ts) c->first_ts = e.ts;
    if (!c->have_ts || e.ts > c->last_ts) c->last_ts = e.ts;
    c->have_ts = 1;
    unsigned mask = lf_detect(&e);
    for (int r = 0; r < LF_RULES; r++) if (mask & (1u << r)) c->rules[r]++;
    if (mask) c->attack_lines++;
    ip_slot *ip = ip_get(c, e.ip, e.ip_len);
    if (ip) {
        ip->count++;
        if (mask) ip->attacks++;
        if (e.status == 401) ip->authfail++;
    }
    size_t pl = 0;
    while (pl < e.path_len && e.path[pl] != '?') pl++;
    if (pl > PATH_KEY - 1) pl = PATH_KEY - 1;
    if (pl) {
        path_slot *ps = path_get(c, e.path, pl);
        if (ps) ps->count++;
    }
}

void lf_feed(lf_ctx *c, const char *buf, size_t len) {
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && buf[j] != '\n') j++;
        int nl = j < len;
        size_t seg = j - i;
        if (c->discarding) {
            if (nl) c->discarding = 0;
        } else if (c->carry_len == 0 && nl && seg <= LF_MAX_LINE) {
            handle_line(c, buf + i, seg);
        } else if (c->carry_len + seg > LF_MAX_LINE) {
            c->lines++;
            c->malformed++;
            c->carry_len = 0;
            c->discarding = !nl;
        } else {
            for (size_t k = 0; k < seg; k++) c->carry[c->carry_len + k] = buf[i + k];
            c->carry_len += seg;
            if (nl) { handle_line(c, c->carry, c->carry_len); c->carry_len = 0; }
        }
        i = nl ? j + 1 : j;
    }
}

void lf_flush(lf_ctx *c) {
    if (c->carry_len) handle_line(c, c->carry, c->carry_len);
    c->carry_len = 0;
    c->discarding = 0;
}

uint64_t lf_attack_lines(const lf_ctx *c) { return c->attack_lines; }

/* ------------------------------------------------------------------ top-N selection */

typedef struct { const char *key; size_t klen; uint32_t v; } top_item;

static int better(const top_item *a, const top_item *b) {
    if (a->v != b->v) return a->v > b->v;
    size_t n = a->klen < b->klen ? a->klen : b->klen;
    for (size_t i = 0; i < n; i++)
        if (a->key[i] != b->key[i]) return (unsigned char)a->key[i] < (unsigned char)b->key[i];
    return a->klen < b->klen;
}

static void top_add(top_item *top, int *cnt, top_item it) {
    int pos = *cnt;
    while (pos > 0 && better(&it, &top[pos - 1])) pos--;
    if (pos >= TOP_N) return;
    int last = *cnt < TOP_N ? *cnt : TOP_N - 1;
    for (int k = last; k > pos; k--) top[k] = top[k - 1];
    top[pos] = it;
    if (*cnt < TOP_N) (*cnt)++;
}

static int top_ips(const lf_ctx *c, int field, uint32_t min, top_item *top) {
    int cnt = 0;
    for (uint32_t i = 0; i < IP_CAP; i++) {
        const ip_slot *s = &c->ips[i];
        if (!s->klen) continue;
        uint32_t v = field == 0 ? s->count : field == 1 ? s->attacks : s->authfail;
        if (v < min) continue;
        top_item it = {s->key, s->klen, v};
        top_add(top, &cnt, it);
    }
    return cnt;
}

static int top_paths(const lf_ctx *c, top_item *top) {
    int cnt = 0;
    for (uint32_t i = 0; i < PATH_CAP; i++) {
        const path_slot *s = &c->paths[i];
        if (!s->klen) continue;
        top_item it = {s->key, s->klen, s->count};
        top_add(top, &cnt, it);
    }
    return cnt;
}

/* ------------------------------------------------------------------ output */

typedef struct { char *p; size_t cap, len; int over; } out_t;

static void put(out_t *o, const char *s, size_t n) {
    if (o->len + n + 1 > o->cap) { o->over = 1; return; }
    for (size_t i = 0; i < n; i++) o->p[o->len + i] = s[i];
    o->len += n;
}
static void puts_(out_t *o, const char *s) { put(o, s, cstrlen(s)); }
static void putu(out_t *o, uint64_t v) {
    char t[24]; int n = 0;
    if (v == 0) t[n++] = '0';
    while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
    char r[24];
    for (int i = 0; i < n; i++) r[i] = t[n - 1 - i];
    put(o, r, (size_t)n);
}
static void puti(out_t *o, int64_t v) {
    if (v < 0) { put(o, "-", 1); putu(o, (uint64_t)(-v)); } else putu(o, (uint64_t)v);
}
/* JSON string: control bytes, quote, backslash and every byte >= 0x7f become \u00XX so the
 * output is always valid UTF-8 whatever an attacker put in the log. */
static void putj(out_t *o, const char *s, size_t n) {
    static const char hx[] = "0123456789abcdef";
    put(o, "\"", 1);
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (ch < 0x20 || ch == '"' || ch == '\\' || ch >= 0x7f) {
            char u[6] = {'\\', 'u', '0', '0', hx[ch >> 4], hx[ch & 15]};
            put(o, u, 6);
        } else put(o, (const char *)&ch, 1);
    }
    put(o, "\"", 1);
}

static const char *const RULE_NAMES[LF_RULES] = {"sqli", "traversal", "xss", "scanner", "shellshock", "log4shell", "sensitive_file"};
static const char *const CLASSES[5] = {"1xx", "2xx", "3xx", "4xx", "5xx"};

static void put_top(out_t *o, const char *name, const char *kname, const top_item *t, int n) {
    puts_(o, ",\""); puts_(o, name); puts_(o, "\":[");
    for (int i = 0; i < n; i++) {
        if (i) puts_(o, ",");
        puts_(o, "{\""); puts_(o, kname); puts_(o, "\":"); putj(o, t[i].key, t[i].klen);
        puts_(o, ",\"count\":"); putu(o, t[i].v); puts_(o, "}");
    }
    puts_(o, "]");
}

size_t lf_report_json(const lf_ctx *c, char *buf, size_t cap) {
    out_t o = {buf, cap, 0, 0};
    top_item t[TOP_N];
    int n;
    puts_(&o, "{\"lines\":"); putu(&o, c->lines);
    puts_(&o, ",\"parsed\":"); putu(&o, c->parsed);
    puts_(&o, ",\"malformed\":"); putu(&o, c->malformed);
    puts_(&o, ",\"bytes\":"); putu(&o, c->bytes);
    puts_(&o, ",\"first_ts\":"); puti(&o, c->have_ts ? c->first_ts : 0);
    puts_(&o, ",\"last_ts\":"); puti(&o, c->have_ts ? c->last_ts : 0);
    puts_(&o, ",\"status\":{");
    for (int i = 0; i < 5; i++) { if (i) puts_(&o, ","); putj(&o, CLASSES[i], 3); puts_(&o, ":"); putu(&o, c->status[i]); }
    puts_(&o, "},\"unique_ips\":"); putu(&o, c->unique_ips);
    puts_(&o, ",\"ip_overflow\":"); putu(&o, c->ip_overflow);
    puts_(&o, ",\"unique_paths\":"); putu(&o, c->unique_paths);
    puts_(&o, ",\"path_overflow\":"); putu(&o, c->path_overflow);
    puts_(&o, ",\"attack_lines\":"); putu(&o, c->attack_lines);
    puts_(&o, ",\"attacks\":{");
    for (int i = 0; i < LF_RULES; i++) { if (i) puts_(&o, ","); putj(&o, RULE_NAMES[i], cstrlen(RULE_NAMES[i])); puts_(&o, ":"); putu(&o, c->rules[i]); }
    puts_(&o, "}");
    n = top_ips(c, 0, 1, t); put_top(&o, "top_ips", "ip", t, n);
    n = top_ips(c, 1, 1, t); put_top(&o, "attackers", "ip", t, n);
    n = top_ips(c, 2, BRUTE_MIN, t); put_top(&o, "auth_failures", "ip", t, n);
    n = top_paths(c, t); put_top(&o, "top_paths", "path", t, n);
    puts_(&o, "}");
    if (o.over) return 0;
    o.p[o.len] = 0;
    return o.len;
}

static void put_pad(out_t *o, const char *s, size_t n, size_t width) {
    put(o, s, n);
    for (size_t i = n; i < width; i++) put(o, " ", 1);
}

size_t lf_report_text(const lf_ctx *c, char *buf, size_t cap) {
    out_t o = {buf, cap, 0, 0};
    top_item t[TOP_N];
    int n;
    puts_(&o, "LogForge report\n===============\n");
    puts_(&o, "lines "); putu(&o, c->lines); puts_(&o, "   parsed "); putu(&o, c->parsed);
    puts_(&o, "   malformed "); putu(&o, c->malformed); puts_(&o, "   bytes "); putu(&o, c->bytes); puts_(&o, "\n");
    puts_(&o, "status ");
    for (int i = 0; i < 5; i++) { puts_(&o, CLASSES[i]); puts_(&o, "="); putu(&o, c->status[i]); puts_(&o, i < 4 ? "  " : "\n"); }
    puts_(&o, "unique clients "); putu(&o, c->unique_ips); puts_(&o, "   unique paths "); putu(&o, c->unique_paths); puts_(&o, "\n\n");
    puts_(&o, "Attack signatures ("); putu(&o, c->attack_lines); puts_(&o, " lines)\n");
    for (int i = 0; i < LF_RULES; i++) {
        puts_(&o, "  "); put_pad(&o, RULE_NAMES[i], cstrlen(RULE_NAMES[i]), 16); putu(&o, c->rules[i]); puts_(&o, "\n");
    }
    struct { const char *title; int kind; uint32_t min; } secs[] = {{"Top clients", 0, 1}, {"Most attack traffic", 1, 1}, {"Auth failures (401)", 2, BRUTE_MIN}};
    for (int s = 0; s < 3; s++) {
        puts_(&o, "\n"); puts_(&o, secs[s].title); puts_(&o, "\n");
        n = top_ips(c, secs[s].kind, secs[s].min, t);
        if (!n) puts_(&o, "  none\n");
        for (int i = 0; i < n; i++) { puts_(&o, "  "); put_pad(&o, t[i].key, t[i].klen, 40); putu(&o, t[i].v); puts_(&o, "\n"); }
    }
    puts_(&o, "\nTop paths\n");
    n = top_paths(c, t);
    if (!n) puts_(&o, "  none\n");
    for (int i = 0; i < n; i++) {
        puts_(&o, "  ");
        size_t k = t[i].klen > 38 ? 38 : t[i].klen;
        for (size_t j = 0; j < k; j++) { char ch = t[i].key[j]; put(&o, (ch >= 0x20 && ch < 0x7f) ? &ch : "?", 1); }
        for (size_t j = k; j < 40; j++) put(&o, " ", 1);
        putu(&o, t[i].v); puts_(&o, "\n");
    }
    if (o.over) return 0;
    o.p[o.len] = 0;
    return o.len;
}
