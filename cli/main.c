#include <stdio.h>
#include <string.h>
#include "../core/logforge.h"

static void usage(void) {
    fputs("usage: logforge [--json] [--fail-on-attacks] [file ...]\n"
          "  reads combined-format access logs from files or stdin ('-')\n"
          "  exit status: 0 ok, 1 attack signatures found with --fail-on-attacks, 2 error\n", stderr);
}

int main(int argc, char **argv) {
    int json = 0, fail = 0, nfiles = 0;
    const char *files[64];
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) json = 1;
        else if (!strcmp(argv[i], "--fail-on-attacks")) fail = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(); return 0; }
        else if (argv[i][0] == '-' && argv[i][1]) { usage(); return 2; }
        else if (nfiles < 64) files[nfiles++] = argv[i];
        else { fputs("too many files\n", stderr); return 2; }
    }
    lf_ctx *c = lf_new();
    if (!c) { fputs("out of memory\n", stderr); return 2; }
    static char buf[1 << 20];
    if (nfiles == 0) files[nfiles++] = "-";
    for (int i = 0; i < nfiles; i++) {
        FILE *f = strcmp(files[i], "-") ? fopen(files[i], "rb") : stdin;
        if (!f) { perror(files[i]); lf_free(c); return 2; }
        size_t n;
        while ((n = fread(buf, 1, sizeof buf, f)) > 0) lf_feed(c, buf, n);
        if (ferror(f)) { perror(files[i]); lf_free(c); return 2; }
        if (f != stdin) fclose(f);
        lf_flush(c); /* a file that does not end in a newline still counts its last line */
    }
    static char out[1 << 16];
    size_t len = json ? lf_report_json(c, out, sizeof out) : lf_report_text(c, out, sizeof out);
    if (!len) { fputs("report too large\n", stderr); lf_free(c); return 2; }
    fwrite(out, 1, len, stdout);
    if (json) fputc('\n', stdout);
    int attacks = lf_attack_lines(c) > 0;
    lf_free(c);
    return fail && attacks ? 1 : 0;
}
