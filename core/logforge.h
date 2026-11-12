/* LogForge core: a freestanding C99 web access log analyzer.
 * No libc is needed by the core, so the same source builds as a native library, a CLI and a
 * WebAssembly module. */
#ifndef LOGFORGE_H
#define LOGFORGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LF_MAX_LINE 8192 /* longer lines are counted as malformed and skipped */

enum {
    LF_SQLI, LF_TRAVERSAL, LF_XSS, LF_SCANNER, LF_SHELLSHOCK, LF_LOG4SHELL, LF_SENSITIVE,
    LF_RULES
};

typedef struct {
    const char *ip;     size_t ip_len;
    const char *method; size_t method_len;
    const char *path;   size_t path_len; /* request target including the query string */
    const char *ref;    size_t ref_len;
    const char *ua;     size_t ua_len;
    int status;
    uint64_t bytes;
    int64_t ts; /* unix seconds, UTC */
} lf_entry;

typedef struct lf_ctx lf_ctx;

/* Parses one combined-format line (no trailing newline). Returns 1 on success, 0 if malformed.
 * The returned views point into `line`. */
int lf_parse_line(const char *line, size_t len, lf_entry *out);

/* Returns a bitmask with bit (1 << LF_xxx) set for every rule the entry triggers. */
unsigned lf_detect(const lf_entry *e);

size_t lf_ctx_size(void);
void lf_init(lf_ctx *c); /* zero-fills a context of lf_ctx_size() bytes */
void lf_feed(lf_ctx *c, const char *buf, size_t len); /* any chunking, lines may span calls */
void lf_flush(lf_ctx *c);                             /* process a final line without newline */

/* Both return the number of bytes written (without terminator), or 0 if `cap` is too small. */
size_t lf_report_json(const lf_ctx *c, char *out, size_t cap);
size_t lf_report_text(const lf_ctx *c, char *out, size_t cap);

uint64_t lf_attack_lines(const lf_ctx *c);

/* Native convenience (not part of the freestanding core, see native.c). */
lf_ctx *lf_new(void);
void lf_free(lf_ctx *c);

#ifdef __cplusplus
}
#endif
#endif
