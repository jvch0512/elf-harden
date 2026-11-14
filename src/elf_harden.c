#include "elf_harden.h"
#include <string.h>

#define ET_EXEC 2
#define ET_DYN 3
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_GNU_STACK 0x6474e551u
#define PT_GNU_RELRO 0x6474e552u
#define PF_X 1u
#define SHT_SYMTAB 2
#define SHT_DYNSYM 11
#define DT_NULL 0
#define DT_TEXTREL 22
#define DT_BIND_NOW 24
#define DT_RPATH 15
#define DT_RUNPATH 29
#define DT_FLAGS 30
#define DT_FLAGS_1 0x6ffffffbu
#define DF_BIND_NOW 8u
#define DF_1_NOW 1u
#define DF_1_PIE 0x08000000u

static int in_range(size_t n, unsigned long long off, unsigned long long len) {
    return off <= n && len <= n - off;
}
static unsigned rd16(const unsigned char *p) { return (unsigned)p[0] | ((unsigned)p[1] << 8); }
static unsigned rd32(const unsigned char *p) { return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24); }
static unsigned long long rd64(const unsigned char *p) { return (unsigned long long)rd32(p) | ((unsigned long long)rd32(p + 4) << 32); }

static int ends_with(const char *s, const char *suf) {
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && strcmp(s + a - b, suf) == 0;
}

static void add_unsafe(eh_info *r, const char *name) {
    size_t len = strlen(r->unsafe);
    size_t add = strlen(name);
    if (len + add + 2 >= sizeof r->unsafe) return;
    if (len) { r->unsafe[len++] = ','; r->unsafe[len] = 0; }
    memcpy(r->unsafe + len, name, add + 1);
}

static void note_symbol(eh_info *r, const char *name) {
    if (strcmp(name, "__stack_chk_fail") == 0) r->canary = 1;
    else if (strcmp(name, "gets") == 0) r->gets = 1;
    else if (strcmp(name, "strcpy") == 0 || strcmp(name, "strcat") == 0 || strcmp(name, "sprintf") == 0 || strcmp(name, "vsprintf") == 0) {
        if (!strstr(r->unsafe, name)) add_unsafe(r, name);
    } else if (strncmp(name, "__", 2) == 0 && ends_with(name, "_chk") && strcmp(name, "__stack_chk_fail") != 0) r->fortify++;
}

int eh_analyze(const unsigned char *buf, size_t n, eh_info *r) {
    memset(r, 0, sizeof *r);
    if (n < 4 || memcmp(buf, "\x7f" "ELF", 4) != 0) return -1;
    if (n < 64) return -3;
    if (buf[4] != 2 || buf[5] != 1) return -2;
    unsigned etype = rd16(buf + 16);
    unsigned long long phoff = rd64(buf + 32), shoff = rd64(buf + 40);
    unsigned phentsize = rd16(buf + 54), phnum = rd16(buf + 56), shentsize = rd16(buf + 58), shnum = rd16(buf + 60);
    if (etype != ET_EXEC && etype != ET_DYN) return -3;
    if (phnum && phentsize < 56) return -3;
    if (shnum && shentsize < 64) return -3;

    int has_stack = 0, has_relro = 0, has_interp = 0;
    unsigned long long dyn_off = 0, dyn_size = 0;
    int have_dyn = 0;
    for (unsigned i = 0; i < phnum; i++) {
        unsigned long long o = phoff + (unsigned long long)i * phentsize;
        if (!in_range(n, o, 56)) return -3;
        const unsigned char *p = buf + o;
        unsigned type = rd32(p), flags = rd32(p + 4);
        if (type == PT_INTERP) has_interp = 1;
        else if (type == PT_GNU_STACK) { has_stack = 1; r->nx = !(flags & PF_X); }
        else if (type == PT_GNU_RELRO) has_relro = 1;
        else if (type == PT_DYNAMIC) { dyn_off = rd64(p + 8); dyn_size = rd64(p + 32); have_dyn = 1; }
    }
    if (!has_stack) r->nx = 0;

    int bind_now = 0, pie_flag = 0;
    if (have_dyn) {
        if (!in_range(n, dyn_off, dyn_size)) return -3;
        for (unsigned long long k = 0; k + 16 <= dyn_size; k += 16) {
            unsigned long long tag = rd64(buf + dyn_off + k), val = rd64(buf + dyn_off + k + 8);
            if (tag == DT_NULL) break;
            if (tag == DT_BIND_NOW) bind_now = 1;
            else if (tag == DT_FLAGS && (val & DF_BIND_NOW)) bind_now = 1;
            else if (tag == DT_FLAGS_1) { if (val & DF_1_NOW) bind_now = 1; if (val & DF_1_PIE) pie_flag = 1; }
            else if (tag == DT_RPATH) r->rpath = 1;
            else if (tag == DT_RUNPATH) r->runpath = 1;
            else if (tag == DT_TEXTREL) r->textrel = 1;
        }
    }
    r->relro = has_relro ? (bind_now ? 2 : 1) : 0;
    r->is_exec = (etype == ET_EXEC) || has_interp || pie_flag;
    r->is_pie = (etype == ET_DYN) && (has_interp || pie_flag);
    r->stripped = 1;

    if (shnum && shoff) {
        if (!in_range(n, shoff, (unsigned long long)shnum * shentsize)) return -3;
        for (unsigned i = 0; i < shnum; i++) {
            const unsigned char *sh = buf + shoff + (unsigned long long)i * shentsize;
            unsigned type = rd32(sh + 4);
            if (type == SHT_SYMTAB) r->stripped = 0;
            if (type != SHT_DYNSYM) continue;
            r->has_dynsym = 1;
            unsigned long long off = rd64(sh + 24), size = rd64(sh + 32), entsize = rd64(sh + 56);
            unsigned link = rd32(sh + 40);
            if (entsize != 24 || link >= shnum || !in_range(n, off, size)) return -3;
            const unsigned char *str_sh = buf + shoff + (unsigned long long)link * shentsize;
            unsigned long long str_off = rd64(str_sh + 24), str_size = rd64(str_sh + 32);
            if (!in_range(n, str_off, str_size)) return -3;
            for (unsigned long long k = 0; k + 24 <= size; k += 24) {
                const unsigned char *sym = buf + off + k;
                unsigned name = rd32(sym);
                unsigned shndx = rd16(sym + 6);
                if (shndx != 0 || name == 0 || name >= str_size) continue; /* only undefined (imported) symbols */
                const char *s = (const char *)(buf + str_off + name);
                size_t maxlen = (size_t)(str_size - name);
                size_t len = 0;
                while (len < maxlen && s[len]) len++;
                if (len == maxlen || len > 255) continue;
                note_symbol(r, s);
            }
        }
    }
    return 0;
}
