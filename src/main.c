#define _POSIX_C_SOURCE 200809L
#include "elf_harden.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_FILE (64u * 1024 * 1024)
#define MAX_FINDINGS 4096

typedef struct { int rank; const char *sev; const char *rule; char where[512]; char msg[300]; } finding;
static finding *fs;
static size_t nf, nfiles, nskipped;

static int rank_of(const char *s) {
    if (!strcmp(s, "critical")) return 0;
    if (!strcmp(s, "high")) return 1;
    if (!strcmp(s, "medium")) return 2;
    if (!strcmp(s, "low")) return 3;
    return 4;
}

static void add(const char *sev, const char *rule, const char *where, const char *msg) {
    if (nf >= MAX_FINDINGS) return;
    finding *f = &fs[nf++];
    f->rank = rank_of(sev); f->sev = sev; f->rule = rule;
    snprintf(f->where, sizeof f->where, "%s", where);
    snprintf(f->msg, sizeof f->msg, "%s", msg);
}

static unsigned char *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 || (unsigned long long)st.st_size > MAX_FILE) { fclose(f); return NULL; }
    unsigned char *b = malloc((size_t)st.st_size + 1);
    if (!b) { fclose(f); return NULL; }
    *n = fread(b, 1, (size_t)st.st_size, f);
    fclose(f);
    return b;
}

static void analyse_file(const char *path, const char *label) {
    size_t n = 0;
    unsigned char *b = slurp(path, &n);
    if (!b) { nskipped++; return; }
    eh_info r;
    int rc = eh_analyze(b, n, &r);
    free(b);
    if (rc == -1) return; /* not ELF: ignore silently */
    nfiles++;
    if (rc == -2) { add("info", "ELF000", label, "unsupported ELF (only ELF64 little-endian is analysed)"); return; }
    if (rc == -3) { add("info", "ELF000", label, "malformed or truncated ELF"); return; }
    char m[300];
    if (!r.nx) add("high", "ELF001", label, "stack is executable (NX off): link with -z noexecstack");
    if (r.is_exec && !r.is_pie) add("high", "ELF002", label, "not position independent: build with -fPIE -pie so ASLR randomises the binary");
    if (r.gets) add("high", "ELF003", label, "imports gets, which cannot be used safely");
    if (r.rpath) add("high", "ELF004", label, "DT_RPATH is set: its library search path overrides LD_LIBRARY_PATH");
    if (r.relro == 0) add("medium", "ELF005", label, "no RELRO: link with -z relro -z now");
    if (r.has_dynsym && !r.canary && r.is_exec) add("medium", "ELF006", label, "no __stack_chk_fail import: no stack protector, or no function needed one; check -fstack-protector-strong");
    if (r.unsafe[0]) { snprintf(m, sizeof m, "imports unsafe functions: %s", r.unsafe); add("medium", "ELF007", label, m); }
    if (r.textrel) add("medium", "ELF008", label, "text relocations: code pages are written at load time");
    if (r.relro == 1) add("low", "ELF009", label, "partial RELRO: the GOT stays writable, link with -z now for full RELRO");
    if (r.runpath) add("low", "ELF010", label, "DT_RUNPATH is set: check it does not point at a writable directory");
    snprintf(m, sizeof m, "%s, NX %s, RELRO %s, canary %s, fortify %d, %s",
             r.is_exec ? (r.is_pie ? "PIE" : "no PIE") : "library", r.nx ? "on" : "off",
             r.relro == 2 ? "full" : r.relro == 1 ? "partial" : "none", r.canary ? "yes" : "no", r.fortify,
             r.stripped ? "stripped" : "not stripped");
    add("info", "ELF011", label, m);
}

static int cmp_names(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void walk(const char *root, const char *dir, int top) {
    DIR *d = opendir(dir);
    if (!d) { nskipped++; return; }
    char **names = NULL; size_t cnt = 0, cap = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (cnt == cap) { cap = cap ? cap * 2 : 32; names = realloc(names, cap * sizeof *names); if (!names) { closedir(d); return; } }
        names[cnt++] = strdup(e->d_name);
    }
    closedir(d);
    qsort(names, cnt, sizeof *names, cmp_names);
    for (size_t i = 0; i < cnt; i++) {
        char path[4096];
        snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        struct stat st;
        if (lstat(path, &st) != 0) { free(names[i]); continue; }
        if (S_ISDIR(st.st_mode)) walk(root, path, 0);
        else if (S_ISREG(st.st_mode)) analyse_file(path, path + strlen(root) + 1);
        free(names[i]);
    }
    free(names);
    (void)top;
}

static int usage(void) {
    fprintf(stderr, "usage: elf-harden PATH [--tsv] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.\n");
    return 2;
}

static int by_sev(const void *a, const void *b) {
    const finding *x = a, *y = b;
    if (x->rank != y->rank) return x->rank - y->rank;
    int c = strcmp(x->where, y->where);
    return c ? c : strcmp(x->rule, y->rule);
}

int main(int argc, char **argv) {
    const char *path = NULL, *fail = NULL;
    int tsv = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--tsv")) tsv = 1;
        else if (!strcmp(argv[i], "--fail-on")) {
            if (++i >= argc || (strcmp(argv[i], "medium") && strcmp(argv[i], "high") && strcmp(argv[i], "critical"))) return usage();
            fail = argv[i];
        } else if (argv[i][0] == '-') return usage();
        else if (path) return usage();
        else path = argv[i];
    }
    if (!path) return usage();
    struct stat st;
    if (stat(path, &st) != 0) { fprintf(stderr, "error: no such file or directory: %s\n", path); return 2; }
    fs = calloc(MAX_FINDINGS, sizeof *fs);
    if (!fs) return 2;
    if (S_ISDIR(st.st_mode)) {
        char root[4096];
        snprintf(root, sizeof root, "%s", path);
        size_t l = strlen(root);
        while (l > 1 && root[l - 1] == '/') root[--l] = 0;
        walk(root, root, 1);
    } else {
        const char *base = strrchr(path, '/');
        analyse_file(path, base ? base + 1 : path);
    }
    qsort(fs, nf, sizeof *fs, by_sev);
    size_t shown = 0;
    for (size_t i = 0; i < nf; i++) if (strcmp(fs[i].rule, "ELF011")) shown++;
    if (tsv) printf("# %zu binaries, %zu findings\n", nfiles, shown);
    else printf("%zu binaries, %zu findings\n", nfiles, shown);
    for (size_t i = 0; i < nf; i++) {
        if (tsv) printf("%s\t%s\t%s\t%s\n", fs[i].sev, fs[i].rule, fs[i].where, fs[i].msg);
        else printf("%-8s %s %s\n         %s\n", fs[i].sev[0] == 'h' ? "HIGH" : fs[i].sev[0] == 'm' ? "MEDIUM" : fs[i].sev[0] == 'l' ? "LOW" : fs[i].sev[0] == 'c' ? "CRITICAL" : "INFO", fs[i].rule, fs[i].where, fs[i].msg);
    }
    int code = 0;
    if (fail) {
        int floor = rank_of(fail);
        for (size_t i = 0; i < nf; i++) if (fs[i].rank <= floor) code = 1;
    }
    free(fs);
    return code;
}
