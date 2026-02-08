#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_FILE="$ROOT_DIR/ELF-Inspector.csproj"
SAMPLES_DIR="$ROOT_DIR/samples"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

run_expect_success() {
  local elf_file="$1"
  local output_name="$2"
  shift 2

  dotnet run --no-build --project "$PROJECT_FILE" -- \
    --file "$elf_file" \
    --output "$output_name" \
    --output-path "$TEMP_DIR" \
    --deterministic "$@" >/dev/null

  local report_file="$TEMP_DIR/$output_name"
  [[ -f "$report_file" ]] || { echo "Missing report file: $report_file" >&2; return 1; }
}

run_expect_failure() {
  local elf_file="$1"
  local output_name="$2"
  shift 2

  if dotnet run --no-build --project "$PROJECT_FILE" -- \
    --file "$elf_file" \
    --output "$output_name" \
    --output-path "$TEMP_DIR" \
    --deterministic "$@" >/dev/null 2>&1; then
    echo "Expected failure, but command succeeded for: $elf_file" >&2
    return 1
  fi
}

echo "[1/5] Build"
dotnet build "$PROJECT_FILE" /clp:ErrorsOnly /m:1 /nodeReuse:false /p:UseSharedCompilation=false >/dev/null

echo "[2/5] Strict header validation rejects invalid variants"
strict_invalid="$TEMP_DIR/invalid-ei-version.bin"
cp "$SAMPLES_DIR/hello_x86_64" "$strict_invalid"
printf '\x00' | dd of="$strict_invalid" bs=1 seek=6 conv=notrunc >/dev/null 2>&1
run_expect_failure "$strict_invalid" "strict-invalid.txt"

strict_invalid_2="$TEMP_DIR/invalid-e-version.bin"
cp "$SAMPLES_DIR/hello_x86_64" "$strict_invalid_2"
printf '\x00\x00\x00\x00' | dd of="$strict_invalid_2" bs=1 seek=20 conv=notrunc >/dev/null 2>&1
run_expect_failure "$strict_invalid_2" "strict-invalid-2.txt"

strict_invalid_3="$TEMP_DIR/invalid-ei-pad.bin"
cp "$SAMPLES_DIR/hello_x86_64" "$strict_invalid_3"
printf '\x01' | dd of="$strict_invalid_3" bs=1 seek=9 conv=notrunc >/dev/null 2>&1
run_expect_failure "$strict_invalid_3" "strict-invalid-3.txt"

strict_invalid_4="$TEMP_DIR/invalid-ph-meta.bin"
cp "$SAMPLES_DIR/hello_x86_64" "$strict_invalid_4"
printf '\x40\x00\x00\x00\x00\x00\x00\x00' | dd of="$strict_invalid_4" bs=1 seek=32 conv=notrunc >/dev/null 2>&1
printf '\x00\x00' | dd of="$strict_invalid_4" bs=1 seek=54 conv=notrunc >/dev/null 2>&1
printf '\x01\x00' | dd of="$strict_invalid_4" bs=1 seek=56 conv=notrunc >/dev/null 2>&1
run_expect_failure "$strict_invalid_4" "strict-invalid-4.txt"

strict_invalid_5="$TEMP_DIR/invalid-sh-meta.bin"
cp "$SAMPLES_DIR/hello_x86_64" "$strict_invalid_5"
printf '\x40\x00\x00\x00\x00\x00\x00\x00' | dd of="$strict_invalid_5" bs=1 seek=40 conv=notrunc >/dev/null 2>&1
printf '\x00\x00' | dd of="$strict_invalid_5" bs=1 seek=58 conv=notrunc >/dev/null 2>&1
printf '\x01\x00' | dd of="$strict_invalid_5" bs=1 seek=60 conv=notrunc >/dev/null 2>&1
run_expect_failure "$strict_invalid_5" "strict-invalid-5.txt"

echo "[3/5] Compat mode accepts legacy header variants"
run_expect_success "$strict_invalid" "compat-ei-version.txt" "--compat-header-validation"
run_expect_success "$strict_invalid_2" "compat-e-version.txt" "--compat-header-validation"
run_expect_success "$strict_invalid_3" "compat-ei-pad.txt" "--compat-header-validation"
run_expect_success "$strict_invalid_4" "compat-ph-meta.txt" "--compat-header-validation"
run_expect_success "$strict_invalid_5" "compat-sh-meta.txt" "--compat-header-validation"

echo "[4/5] Deterministic mutation smoke matrix"
for i in $(seq 0 31); do
  mutated="$TEMP_DIR/mut-$i.bin"
  cp "$SAMPLES_DIR/busybox" "$mutated"
  # Mutate deterministic offsets in ELF ident/header region.
  offset=$(( (i * 7) % 96 ))
  value=$(( (i * 13 + 17) % 256 ))
  printf "\\$(printf '%03o' "$value")" | dd of="$mutated" bs=1 seek="$offset" conv=notrunc >/dev/null 2>&1

  # Either success or controlled parser failure are acceptable for fuzz-like input.
  dotnet run --no-build --project "$PROJECT_FILE" -- \
    --file "$mutated" \
    --output "mut-$i.txt" \
    --output-path "$TEMP_DIR" \
    --deterministic >/dev/null 2>&1 || true
done

echo "[5/5] Strict parser validates section-string-index consistency"
strict_invalid_6="$TEMP_DIR/invalid-shstrndx.bin"
cp "$SAMPLES_DIR/hello_x86_64" "$strict_invalid_6"
printf '\x02\x00' | dd of="$strict_invalid_6" bs=1 seek=60 conv=notrunc >/dev/null 2>&1
printf '\x02\x00' | dd of="$strict_invalid_6" bs=1 seek=62 conv=notrunc >/dev/null 2>&1
run_expect_failure "$strict_invalid_6" "strict-invalid-6.txt"
run_expect_success "$strict_invalid_6" "compat-shstrndx.txt" "--compat-header-validation"

echo "P0 conformance matrix successful"
