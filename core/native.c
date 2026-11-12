#include <stdlib.h>
#include "logforge.h"

lf_ctx *lf_new(void) { return (lf_ctx *)calloc(1, lf_ctx_size()); }
void lf_free(lf_ctx *c) { free(c); }
