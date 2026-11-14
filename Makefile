CFLAGS ?= -std=c11 -Wall -Wextra -O2

build:
	$(CC) $(CFLAGS) -o elf-harden src/elf_harden.c src/main.c

test: build
	$(CC) $(CFLAGS) -g -fsanitize=address,undefined -o tests/run tests/test.c src/elf_harden.c && ./tests/run

sample: build
	mkdir -p docs site
	./elf-harden examples/bin > docs/sample-output.txt; true
	./elf-harden examples/bin --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "elf-harden" "Checks Linux binaries for PIE, NX, RELRO, stack canary, FORTIFY, RPATH and unsafe imports, like checksec but a single small program. C." "Small binaries built from a toy program with different compiler flags."
