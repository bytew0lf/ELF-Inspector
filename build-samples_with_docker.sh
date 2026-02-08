#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES_DIR="${SAMPLES_DIR:-$ROOT_DIR/samples}"
DEBIAN_IMAGE="${DEBIAN_IMAGE:-debian:trixie}"
ALPINE_IMAGE="${ALPINE_IMAGE:-alpine:latest}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found in PATH" >&2
  exit 1
fi

mkdir -p "$SAMPLES_DIR"

echo '#include <stdio.h>' > "$SAMPLES_DIR/hello.c" && \
echo 'int main(){ printf("Hello from %s!\\n", "ARCH"); return 0; }' >> "$SAMPLES_DIR/hello.c" && \

docker run --rm \
  -v "$SAMPLES_DIR":/home/workspace \
  "$DEBIAN_IMAGE" \
  bash -lc '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  nano \
  build-essential \
  gcc-multilib-* \
  g++-x86-64-linux-gnu \
  g++-x86-64-linux-gnux32 \
  g++-i686-linux-gnu \
  g++-mingw-w64-x86-64 \
  g++-mingw-w64-x86-64-posix \
  g++-mingw-w64-x86-64-win32 \
  g++-aarch64-linux-gnu \
  g++-arm-linux-gnueabihf \
  g++-arm-linux-gnueabi \
  g++-mips-linux-gnu \
  g++-mips64-linux-gnuabi64 \
  g++-mips64el-linux-gnuabi64 \
  g++-mipsel-linux-gnu \
  g++-mipsisa32r6-linux-gnu \
  g++-mipsisa32r6el-linux-gnu \
  g++-mipsisa64r6-linux-gnuabi64 \
  g++-mipsisa64r6el-linux-gnuabi64 \
  g++-powerpc-linux-gnu \
  g++-powerpc64le-linux-gnu \
  g++-riscv64-linux-gnu \
  g++-s390x-linux-gnu \
  g++-sparc64-linux-gnu \
  gcc-x86-64-linux-gnu \
  gcc-x86-64-linux-gnux32 \
  gcc-i686-linux-gnu \
  gcc-aarch64-linux-gnu \
  gcc-arm-linux-gnueabihf \
  gcc-arm-linux-gnueabi \
  gcc-mips-linux-gnu \
  gcc-mips64-linux-gnuabi64 \
  gcc-mips64el-linux-gnuabi64 \
  gcc-mipsel-linux-gnu \
  gcc-mipsisa32r6-linux-gnu \
  gcc-mipsisa32r6el-linux-gnu \
  gcc-mipsisa64r6-linux-gnuabi64 \
  gcc-mipsisa64r6el-linux-gnuabi64 \
  gcc-powerpc-linux-gnu \
  gcc-powerpc64le-linux-gnu \
  gcc-riscv64-linux-gnu \
  gcc-s390x-linux-gnu \
  gcc-sparc64-linux-gnu

rm -f /home/workspace/hello_* /home/workspace/nano

build_sample() {
  local compiler="$1"
  local output="$2"
  if command -v "$compiler" >/dev/null 2>&1; then
    "$compiler" /home/workspace/hello.c -o "/home/workspace/$output"
    echo "built: $output"
  else
    echo "skip: $output (missing compiler $compiler)"
  fi
}

build_sample sparc64-linux-gnu-gcc hello_sparc64
build_sample x86_64-linux-gnu-gcc hello_x86_64
build_sample x86_64-linux-gnux32-gcc hello_x86
build_sample i686-linux-gnu-gcc hello_i686
build_sample aarch64-linux-gnu-gcc hello_arm64
build_sample arm-linux-gnueabihf-gcc hello_armhf
build_sample arm-linux-gnueabi-gcc hello_arm
build_sample mips-linux-gnu-gcc hello_mips
build_sample mips64-linux-gnuabi64-gcc hello_mips64
build_sample mips64el-linux-gnuabi64-gcc hello_mips64el
build_sample mipsel-linux-gnu-gcc hello_mipsel
build_sample mipsisa32r6-linux-gnu-gcc hello_mipsisa32r6
build_sample mipsisa32r6el-linux-gnu-gcc hello_mipsisa32r6el
build_sample mipsisa64r6-linux-gnuabi64-gcc hello_mipsisa64r6
build_sample mipsisa64r6el-linux-gnuabi64-gcc hello_mipsisa64r6el
build_sample powerpc-linux-gnu-gcc hello_ppc
build_sample powerpc64le-linux-gnu-gcc hello_ppc64le
build_sample riscv64-linux-gnu-gcc hello_riscv64
build_sample s390x-linux-gnu-gcc hello_s390x
build_sample x86_64-w64-mingw32-gcc hello_w64_x86_64
build_sample x86_64-w64-mingw32-gcc-posix hello_w64_x86_64_posix
build_sample x86_64-w64-mingw32-gcc-win32 hello_w64_x86_64_win32

cp /bin/nano /home/workspace/nano
'

docker run --rm \
  -v "$SAMPLES_DIR":/home/workspace \
  "$ALPINE_IMAGE" \
  sh -c 'cp /bin/busybox /home/workspace/busybox'

echo "Samples written to: $SAMPLES_DIR"
