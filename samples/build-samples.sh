#!/usr/bin/env bash
set -euo pipefail

WORK_DIR="${WORK_DIR:-/home/workspace}"

echo '#include <stdio.h>' > "$WORK_DIR/hello.c"
echo 'int main(){ printf("Hello from %s!\n", "ARCH"); return 0; }' >> "$WORK_DIR/hello.c"

rm -f "$WORK_DIR"/hello_*

# native 64-bit (x86_64)
x86_64-linux-gnu-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_x86_64"

# i386 (32-bit)
i686-linux-gnu-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_i686"

# RiscV 64
riscv64-linux-gnu-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_riscv64"

# MIPS
mips-linux-gnu-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_mips"
mips64-linux-gnuabi64-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_mips64"
mipsel-linux-gnu-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_mipsel"
mips64el-linux-gnuabi64-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_mips64el"
mipsisa32r6-linux-gnu-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_mipsisa32r6"
mipsisa32r6el-linux-gnu-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_mipsisa32r6el"
mipsisa64r6-linux-gnuabi64-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_mipsisa64r6"
mipsisa64r6el-linux-gnuabi64-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_mipsisa64r6el"

# armhf
arm-linux-gnueabihf-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_armhf"

# arm64
aarch64-linux-gnu-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_arm64"

# ppc & ppc64le
powerpc-linux-gnu-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_ppc"
powerpc64le-linux-gnu-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_ppc64le"

# s390x
s390x-linux-gnu-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_s390x"

# SPARC
sparc64-linux-gnu-gcc "$WORK_DIR/hello.c" -o "$WORK_DIR/hello_sparc64"

echo Done.
