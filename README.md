# elf-harden

elf-harden reads ELF executables and shared libraries and reports which exploit mitigations are missing: position independent code (ASLR), non-executable stack, RELRO, stack protector, FORTIFY_SOURCE, RPATH and RUNPATH, text relocations and imports of dangerous functions such as `gets`. It parses the file itself and never runs it, so it is safe on suspicious binaries.

**Live demo:** https://jvch0512.github.io/elf-harden/ (Small binaries built from a toy program with different compiler flags.)

C11, no libraries (reads ELF64 little-endian files). The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
make
./elf-harden /usr/bin
./elf-harden ./build/myservice --tsv
./elf-harden ./dist --fail-on high      # exit 1 in CI when a binary lacks PIE, NX or has RPATH
```

Pass a file or a directory. Directories are walked recursively and every regular file that starts with the ELF magic is analysed.

| Rule | Severity | What it catches |
|---|---|---|
| ELF001 | high | executable stack (no `PT_GNU_STACK`, or it is executable) |
| ELF002 | high | not position independent (fixed load address, ASLR does not randomise the binary) |
| ELF003 | high | `gets` imported |
| ELF004 | high | `DT_RPATH` set: library search path that takes priority over the environment |
| ELF005 | medium | no RELRO at all |
| ELF006 | medium | no stack protector symbol (`__stack_chk_fail`) |
| ELF007 | medium | unsafe functions imported (`strcpy`, `strcat`, `sprintf`, `vsprintf`) |
| ELF008 | medium | text relocations (`DT_TEXTREL`) |
| ELF009 | low | partial RELRO (GOT stays writable: link with `-z now`) |
| ELF010 | low | `DT_RUNPATH` set |
| ELF011 | info | symbol table stripped, hardening summary |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- ELF64 little-endian only (x86-64, AArch64, RISC-V 64). 32-bit and big-endian files are reported as unsupported.
- The stack protector check is by symbol: a function with no arrays may legitimately have no canary even in a protected build. Treat ELF006 as a prompt to check the build flags.
- Static binaries have no dynamic symbols, so import based rules (ELF003, ELF006, ELF007) cannot see inside them.
- It reports the build, not the runtime: kernel settings (ASLR level, `noexec` mounts) are not read.

## Where it fits

Build and release reviews, container image audits and CTF or incident triage: a fast, dependency-free check that a delivered binary was built with the expected hardening flags.

## Tests

```bash
make test    # 64 checks
```

MIT.
