#!/bin/sh
# Rebuilds the sample binaries. The committed binaries are what the sample output is generated from.
set -e
cd "$(dirname "$0")"
cat > /tmp/eh-demo.c <<'C'
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char buf[64];
    if (argc > 1) { strcpy(buf, argv[1]); printf("%s\n", buf); }
    return 0;
}
C
gcc -O2 -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now -o bin/hardened /tmp/eh-demo.c
gcc -O2 -fno-pie -no-pie -fno-stack-protector -U_FORTIFY_SOURCE -Wl,-z,norelro -o bin/legacy /tmp/eh-demo.c
gcc -O2 -fPIE -pie -fno-stack-protector -Wl,-z,relro -Wl,-z,execstack -Wl,-rpath,/opt/app/lib -o bin/sloppy /tmp/eh-demo.c
strip bin/hardened
