/* Unit tests for the C core. Built with ASan and UBSan by `make test-c`. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../core/logforge.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static lf_entry parse_ok(const char *line) {
    lf_entry e;
    memset(&e, 0, sizeof e);
    int ok = lf_parse_line(line, strlen(line), &e);
    CHECK(ok);
    return e;
}

static int bad(const char *line) {
    lf_entry e;
    return !lf_parse_line(line, strlen(line), &e);
}

static void test_parse(void) {
    lf_entry e = parse_ok("192.0.2.10 - alice [10/Oct/2026:13:55:36 +0000] \"GET /a/b?x=1 HTTP/1.1\" 404 1234 \"https://r.test/\" \"UA/1\"");
    CHECK(e.ip_len == 10 && !memcmp(e.ip, "192.0.2.10", 10));
    CHECK(e.method_len == 3 && !memcmp(e.method, "GET", 3));
    CHECK(e.path_len == 8 && !memcmp(e.path, "/a/b?x=1", 8));
    CHECK(e.status == 404 && e.bytes == 1234 && e.ts == 1791640536);
    CHECK(e.ref_len == 15 && e.ua_len == 4 && !memcmp(e.ua, "UA/1", 4));

    e = parse_ok("2001:db8::1 - - [01/Jan/2030:00:00:00 -0530] \"GET / HTTP/1.1\" 200 - \"-\" \"-\"");
    CHECK(e.ip_len == 11 && e.bytes == 0);
    CHECK(e.ts == 1893456000 + 5 * 3600 + 30 * 60); /* a negative offset means local time is behind UTC */

    e = parse_ok("192.0.2.1 - - [29/Feb/2028:23:59:60 +0000] \"-\" 400 0");
    CHECK(e.path_len == 0 && e.method_len == 1 && e.ua_len == 0);

    e = parse_ok("192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] \"GET /x HTTP/1.1\" 200 5 \"-\" \"a \\\"quoted\\\" b\"");
    CHECK(e.ua_len == strlen("a \\\"quoted\\\" b"));
}

static void test_parse_rejects(void) {
    CHECK(bad(""));
    CHECK(bad("garbage"));
    CHECK(bad("192.0.2.1 - - [10/Foo/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1"));
    CHECK(bad("192.0.2.1 - - [30/Feb/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1"));
    CHECK(bad("192.0.2.1 - - [29/Feb/2027:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1"));
    CHECK(bad("192.0.2.1 - - [10/Oct/2026:24:00:00 +0000] \"GET / HTTP/1.1\" 200 1"));
    CHECK(bad("192.0.2.1 - - [10/Oct/1969:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1"));
    CHECK(bad("192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 099 1"));
    CHECK(bad("192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 600 1"));
    CHECK(bad("192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 200 12x"));
    CHECK(bad("192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1234567890123456789"));
    CHECK(bad("192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] \"GET / HTTP/1.1 200 1"));            /* unterminated quote */
    CHECK(bad("192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1 \"a\" \"b\" extra"));
    CHECK(bad("192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1 \"only-ref\""));
    CHECK(bad("host.example.com - - [10/Oct/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1")); /* names are not addresses */
    CHECK(bad("1111111111111111111111111111111111111111111111111 - - [10/Oct/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1"));
    CHECK(bad("192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] \"GET\\"));  /* backslash at the very end */
    CHECK(bad("192.0.2.1 -"));
}

static unsigned detect(const char *path, const char *ua, const char *ref) {
    lf_entry e;
    memset(&e, 0, sizeof e);
    e.path = path; e.path_len = strlen(path);
    e.ua = ua; e.ua_len = strlen(ua);
    e.ref = ref; e.ref_len = strlen(ref);
    return lf_detect(&e);
}
#define BIT(r) (1u << (r))

static void test_detect(void) {
    CHECK(detect("/", "Mozilla/5.0", "-") == 0);
    CHECK(detect("/p?id=1%20UNION%20SELECT%201", "x", "-") == BIT(LF_SQLI));
    CHECK(detect("/p?id=1+uNiOn+SeLeCt+1", "x", "-") == BIT(LF_SQLI));
    CHECK(detect("/p?x=1' OR '1'='1", "x", "-") & BIT(LF_SQLI));
    CHECK(detect("/f?file=..%2f..%2fetc%2fpasswd", "x", "-") == BIT(LF_TRAVERSAL));
    CHECK(detect("/f?file=..\\..\\boot.ini", "x", "-") & BIT(LF_TRAVERSAL));
    CHECK(detect("/s?q=%3Cscript%3Ealert(1)", "x", "-") == BIT(LF_XSS));
    CHECK(detect("/", "SQLMap/1.7", "-") == BIT(LF_SCANNER));
    CHECK(detect("/", "x", "() { :;}; echo") == BIT(LF_SHELLSHOCK));
    CHECK(detect("/", "${JNDI:ldap://a/b}", "-") == BIT(LF_LOG4SHELL));
    CHECK(detect("/", "x", "${jndi:ldap://a/b}") == BIT(LF_LOG4SHELL));
    CHECK(detect("/%24%7Bjndi:ldap://a/b%7D", "x", "-") == BIT(LF_LOG4SHELL));
    CHECK(detect("/.env", "x", "-") == BIT(LF_SENSITIVE));
    CHECK(detect("/backup/.GIT/config", "x", "-") == BIT(LF_SENSITIVE));
    CHECK(detect("/page?next=/.env", "x", "-") == 0); /* the query string is not a file request */
    CHECK(detect("/a?x=%2e%2e%2f", "x", "-") == BIT(LF_TRAVERSAL));
    CHECK(detect("/p?id=1%2", "x", "-") == 0);        /* truncated escape stays literal and harmless */
    CHECK(detect("/p?id=100%", "x", "-") == 0);
    CHECK(detect("/p?id=%zz", "x", "-") == 0);
    unsigned multi = detect("/.env?q=union select", "nikto", "-");
    CHECK(multi == (BIT(LF_SQLI) | BIT(LF_SCANNER) | BIT(LF_SENSITIVE)));
    char big[4000];
    memset(big, 'a', sizeof big - 1); big[sizeof big - 1] = 0;
    CHECK(detect(big, big, big) == 0); /* oversized input is truncated, never overflows */
}

static char *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)sz + 1);
    *n = fread(b, 1, (size_t)sz, f);
    fclose(f);
    b[*n] = 0;
    return b;
}

static void test_fixture(void) {
    size_t n;
    char *data = slurp("fixtures/sample.log", &n);
    CHECK(data != 0);
    if (!data) return;
    char whole[1 << 14];
    lf_ctx *c = lf_new();
    lf_feed(c, data, n);
    lf_flush(c);
    size_t len = lf_report_json(c, whole, sizeof whole);
    CHECK(len > 0);
    CHECK(strstr(whole, "\"lines\":32,\"parsed\":29,\"malformed\":3,\"bytes\":23340"));
    CHECK(strstr(whole, "\"first_ts\":1791633900,\"last_ts\":1791641465"));
    CHECK(strstr(whole, "\"status\":{\"1xx\":0,\"2xx\":11,\"3xx\":1,\"4xx\":16,\"5xx\":1}"));
    CHECK(strstr(whole, "\"unique_ips\":6"));
    CHECK(strstr(whole, "\"attack_lines\":8"));
    CHECK(strstr(whole, "\"attacks\":{\"sqli\":1,\"traversal\":1,\"xss\":2,\"scanner\":3,\"shellshock\":1,\"log4shell\":1,\"sensitive_file\":2}"));
    CHECK(strstr(whole, "\"top_ips\":[{\"ip\":\"192.0.2.55\",\"count\":12},{\"ip\":\"192.0.2.10\",\"count\":8},{\"ip\":\"198.51.100.7\",\"count\":3},{\"ip\":\"203.0.113.9\",\"count\":3}"));
    CHECK(strstr(whole, "\"auth_failures\":[{\"ip\":\"192.0.2.55\",\"count\":12}]"));
    CHECK(lf_attack_lines(c) == 8);

    /* Chunking must never change the result: feed one byte at a time and in odd sizes. */
    for (size_t step = 1; step < 200; step = step * 3 + 1) {
        lf_ctx *d = lf_new();
        for (size_t i = 0; i < n; i += step) lf_feed(d, data + i, (i + step <= n) ? step : n - i);
        lf_flush(d);
        char out[1 << 14];
        size_t l2 = lf_report_json(d, out, sizeof out);
        CHECK(l2 == len && !memcmp(out, whole, len));
        lf_free(d);
    }
    char small[10];
    CHECK(lf_report_json(c, small, sizeof small) == 0);
    CHECK(lf_report_text(c, small, sizeof small) == 0);
    char text[1 << 14];
    CHECK(lf_report_text(c, text, sizeof text) > 0 && strstr(text, "Attack signatures (8 lines)"));
    lf_free(c);
    free(data);
}

static void test_robustness(void) {
    lf_ctx *c = lf_new();
    /* a final line without a newline is only counted after flush */
    const char *line = "192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"x\"";
    lf_feed(c, line, strlen(line));
    char out[1 << 14];
    lf_report_json(c, out, sizeof out);
    CHECK(strstr(out, "\"lines\":0"));
    lf_flush(c);
    lf_report_json(c, out, sizeof out);
    CHECK(strstr(out, "\"lines\":1,\"parsed\":1"));
    lf_free(c);

    /* over-long lines, split over several feeds, are one malformed line and do not leak into the next */
    c = lf_new();
    char *junk = malloc(20000);
    memset(junk, 'A', 20000);
    lf_feed(c, junk, 10000);
    lf_feed(c, junk, 10000);
    lf_feed(c, "\n", 1);
    lf_feed(c, line, strlen(line));
    lf_feed(c, "\n", 1);
    lf_report_json(c, out, sizeof out);
    CHECK(strstr(out, "\"lines\":2,\"parsed\":1,\"malformed\":1"));
    lf_free(c);
    free(junk);

    /* binary garbage, NULs and control bytes */
    c = lf_new();
    unsigned char g[4096];
    for (size_t i = 0; i < sizeof g; i++) g[i] = (unsigned char)((i * 131 + 7) & 0xff);
    lf_feed(c, (char *)g, sizeof g);
    lf_flush(c);
    CHECK(lf_report_json(c, out, sizeof out) > 0);
    lf_free(c);

    /* hostile paths: invalid UTF-8 and quotes must still produce valid, escaped JSON */
    c = lf_new();
    const char *evil = "192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] \"GET /\xff\xfe\\\"<>\x01 HTTP/1.1\" 200 1 \"-\" \"x\"\n";
    lf_feed(c, evil, strlen(evil));
    lf_report_json(c, out, sizeof out);
    CHECK(strstr(out, "\"path\":\"/\\u00ff\\u00fe\\u005c\\u0022<>\\u0001\""));
    for (const unsigned char *p = (const unsigned char *)out; *p; p++) CHECK(*p < 0x7f);
    lf_free(c);
}

static void test_table_limits(void) {
    lf_ctx *c = lf_new();
    char line[256], out[1 << 14];
    for (int i = 0; i < 100000; i++) {
        int n = snprintf(line, sizeof line, "10.%d.%d.%d - - [10/Oct/2026:13:55:36 +0000] \"GET /p%d HTTP/1.1\" 200 1 \"-\" \"x\"\n", (i >> 16) & 255, (i >> 8) & 255, i & 255, i);
        lf_feed(c, line, (size_t)n);
    }
    lf_report_json(c, out, sizeof out);
    CHECK(strstr(out, "\"unique_ips\":90000"));
    CHECK(strstr(out, "\"ip_overflow\":10000"));
    CHECK(strstr(out, "\"unique_paths\":45000"));
    CHECK(strstr(out, "\"parsed\":100000"));
    lf_free(c);
}

int main(void) {
    test_parse();
    test_parse_rejects();
    test_detect();
    test_fixture();
    test_robustness();
    test_table_limits();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
