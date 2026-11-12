/* WebAssembly entry points. Static buffers keep the module free of any allocator. */
#include "logforge.h"

#define EXPORT(n) __attribute__((export_name(n)))

/* The context is large, so it lives in .bss as a raw byte array sized at build time. */
#ifndef LF_CTX_BYTES
#error "define LF_CTX_BYTES (use: make wasm)"
#endif
static unsigned char CTX[LF_CTX_BYTES] __attribute__((aligned(16)));
static char IN[1 << 20];
static char OUT[1 << 16];

static lf_ctx *lf_wasm_ctx(void) { return (lf_ctx *)CTX; }

EXPORT("lf_in_ptr") uintptr_t wasm_in_ptr(void) { return (uintptr_t)IN; }
EXPORT("lf_in_cap") uint32_t wasm_in_cap(void) { return (uint32_t)sizeof IN; }
EXPORT("lf_out_ptr") uintptr_t wasm_out_ptr(void) { return (uintptr_t)OUT; }
EXPORT("lf_ctx_bytes") uint32_t wasm_ctx_bytes(void) { return (uint32_t)lf_ctx_size(); }
EXPORT("lf_reset") void wasm_reset(void) { lf_init(lf_wasm_ctx()); }
EXPORT("lf_feed_in") void wasm_feed_in(uint32_t n) { if (n <= sizeof IN) lf_feed(lf_wasm_ctx(), IN, n); }
EXPORT("lf_finish") uint32_t wasm_finish(void) {
    lf_flush(lf_wasm_ctx());
    return (uint32_t)lf_report_json(lf_wasm_ctx(), OUT, sizeof OUT);
}
