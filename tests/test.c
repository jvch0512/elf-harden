#define _POSIX_C_SOURCE 200809L
#include "../src/elf_harden.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/wait.h>
#define WEXIT(s) (WIFEXITED(s) ? WEXITSTATUS(s) : -1)
static int passed, failed;
#define CHECK(c) do { if (c) passed++; else { failed++; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static unsigned char *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long l = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc((size_t)l + 1);
    *n = fread(b, 1, (size_t)l, f);
    fclose(f);
    return b;
}

static const char *PROG =
    "#include <stdio.h>\n#include <string.h>\n"
    "int main(int argc, char **argv) { char b[64]; if (argc > 1) { strcpy(b, argv[1]); sprintf(b, \"%s\", argv[0]); puts(b); } return 0; }\n";
/* gets() is gone from recent glibc headers and from new links, so declare it and leave the import unresolved: the checker only reads the import table. */
static const char *GETS_PROG = "extern char *gets(char *);\nint main(void) { char b[16]; gets(b); return b[0]; }\n";

static int build(const char *src, const char *flags, const char *out) {
    char cmd[1024];
    FILE *f = fopen("/tmp/eh-test.c", "w"); fputs(src, f); fclose(f);
    snprintf(cmd, sizeof cmd, "gcc -w -O2 %s -o %s /tmp/eh-test.c >/dev/null 2>&1", flags, out);
    return system(cmd);
}

static int analyse(const char *path, eh_info *r) {
    size_t n; unsigned char *b = slurp(path, &n);
    if (!b) return -99;
    int rc = eh_analyze(b, n, r);
    free(b);
    return rc;
}

static unsigned long long rng = 88172645463325252ULL;
static unsigned next(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (unsigned)(rng >> 11); }

int main(void) {
    eh_info r;
    const char *out = "/tmp/eh-test-bin";

    /* hardened build */
    CHECK(build(PROG, "-fPIE -pie -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now -Wl,-z,noexecstack", out) == 0);
    CHECK(analyse(out, &r) == 0);
    CHECK(r.is_exec && r.is_pie); CHECK(r.nx); CHECK(r.relro == 2); CHECK(r.canary); CHECK(r.fortify >= 1);
    CHECK(!r.rpath && !r.runpath && !r.textrel); CHECK(!r.stripped); CHECK(r.has_dynsym);

    /* stripped keeps dynamic symbols */
    CHECK(system("strip /tmp/eh-test-bin") == 0);
    CHECK(analyse(out, &r) == 0); CHECK(r.stripped); CHECK(r.canary);

    /* legacy build */
    CHECK(build(PROG, "-fno-pie -no-pie -fno-stack-protector -U_FORTIFY_SOURCE -Wl,-z,norelro", out) == 0);
    CHECK(analyse(out, &r) == 0);
    CHECK(r.is_exec && !r.is_pie); CHECK(r.relro == 0); CHECK(!r.canary); CHECK(r.fortify == 0);
    CHECK(strstr(r.unsafe, "strcpy") != NULL);

    /* partial RELRO */
    CHECK(build(PROG, "-fPIE -pie -Wl,-z,relro -Wl,-z,lazy", out) == 0);
    CHECK(analyse(out, &r) == 0); CHECK(r.relro == 1);

    /* full RELRO */
    CHECK(build(PROG, "-fPIE -pie -Wl,-z,relro -Wl,-z,now", out) == 0);
    CHECK(analyse(out, &r) == 0); CHECK(r.relro == 2);

    /* executable stack */
    CHECK(build(PROG, "-Wl,-z,execstack", out) == 0);
    CHECK(analyse(out, &r) == 0); CHECK(!r.nx);
    CHECK(build(PROG, "-Wl,-z,noexecstack", out) == 0);
    CHECK(analyse(out, &r) == 0); CHECK(r.nx);

    /* rpath vs runpath */
    CHECK(build(PROG, "-Wl,--disable-new-dtags -Wl,-rpath,/opt/lib", out) == 0);
    CHECK(analyse(out, &r) == 0); CHECK(r.rpath && !r.runpath);
    CHECK(build(PROG, "-Wl,--enable-new-dtags -Wl,-rpath,/opt/lib", out) == 0);
    CHECK(analyse(out, &r) == 0); CHECK(r.runpath && !r.rpath);

    /* gets */
    CHECK(build(GETS_PROG, "-fPIE -pie -Wl,--unresolved-symbols=ignore-all", out) == 0);
    CHECK(analyse(out, &r) == 0); CHECK(r.gets);

    /* shared library: not an executable, never "not PIE" */
    CHECK(build("int f(int x) { return x + 1; }\n", "-shared -fPIC", out) == 0);
    CHECK(analyse(out, &r) == 0); CHECK(!r.is_exec && !r.is_pie);

    /* static binary: no dynamic symbols */
    if (build(PROG, "-static", out) == 0) {
        CHECK(analyse(out, &r) == 0); CHECK(!r.has_dynsym); CHECK(r.is_exec);
    }

    /* non ELF and unsupported inputs */
    CHECK(eh_analyze((const unsigned char *)"hello", 5, &r) == -1);
    CHECK(eh_analyze((const unsigned char *)"", 0, &r) == -1);
    unsigned char hdr[64] = {0x7f, 'E', 'L', 'F', 1, 1, 1};
    CHECK(eh_analyze(hdr, 64, &r) == -2);               /* 32-bit */
    unsigned char be[64] = {0x7f, 'E', 'L', 'F', 2, 2, 1};
    CHECK(eh_analyze(be, 64, &r) == -2);                /* big endian */
    CHECK(eh_analyze((const unsigned char *)"\x7f" "ELF", 4, &r) == -3);  /* truncated header */

    /* truncation and corruption never crash (ASan/UBSan are on) */
    CHECK(build(PROG, "-fPIE -pie", out) == 0);
    size_t n; unsigned char *b = slurp(out, &n);
    CHECK(b != NULL);
    int crashes = 0;
    for (size_t cut = 0; cut < n; cut += (n / 400) + 1) { int rc = eh_analyze(b, cut, &r); if (rc > 0) crashes++; }
    CHECK(crashes == 0);
    unsigned char *m = malloc(n);
    for (int i = 0; i < 3000; i++) {
        memcpy(m, b, n);
        int muts = 1 + (int)(next() % 8);
        for (int k = 0; k < muts; k++) m[next() % (n < 4096 ? n : 4096)] = (unsigned char)next();   /* headers and tables live early */
        if (i % 3 == 0) m[next() % n] = (unsigned char)next();
        eh_analyze(m, n, &r);
        if (i % 7 == 0) eh_analyze(m, next() % n, &r);
    }
    CHECK(1);
    free(m); free(b);

    /* CLI */
    CHECK(system("./elf-harden examples/bin >/dev/null") == 0);
    CHECK(WEXIT(system("./elf-harden examples/bin --fail-on high >/dev/null")) == 1);
    CHECK(WEXIT(system("./elf-harden examples/bin/hardened --fail-on medium >/dev/null")) == 0);
    CHECK(WEXIT(system("./elf-harden /no/such/path >/dev/null 2>&1")) == 2);
    CHECK(WEXIT(system("./elf-harden >/dev/null 2>&1")) == 2);
    CHECK(WEXIT(system("./elf-harden examples/bin --bogus >/dev/null 2>&1")) == 2);
    CHECK(WEXIT(system("./elf-harden examples/bin --fail-on nope >/dev/null 2>&1")) == 2);

    printf("%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
