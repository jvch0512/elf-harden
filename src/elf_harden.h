#ifndef ELF_HARDEN_H
#define ELF_HARDEN_H
#include <stddef.h>

typedef struct {
    int is_pie;        /* position independent executable (ASLR for the binary) */
    int is_exec;       /* has an interpreter or is ET_EXEC: an executable, not a library */
    int nx;            /* PT_GNU_STACK present and not executable */
    int relro;         /* 0 none, 1 partial, 2 full */
    int canary;        /* imports __stack_chk_fail */
    int fortify;       /* number of imported *_chk functions */
    int rpath;         /* DT_RPATH */
    int runpath;       /* DT_RUNPATH */
    int textrel;       /* DT_TEXTREL */
    int stripped;      /* no .symtab */
    int has_dynsym;    /* dynamic symbols were available */
    int gets;          /* imports gets */
    char unsafe[96];   /* comma separated unsafe imports other than gets */
} eh_info;

/* Returns 0 on success, -1 if the buffer is not an ELF file, -2 if it is an unsupported ELF (32-bit or big-endian),
   -3 if the ELF is malformed or truncated. info is zeroed first. */
int eh_analyze(const unsigned char *buf, size_t n, eh_info *info);

#endif
