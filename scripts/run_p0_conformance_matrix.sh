#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_FILE="$ROOT_DIR/ELF-Inspector.csproj"
SAMPLES_DIR="$ROOT_DIR/samples"
LIST_ELFS_SCRIPT="$ROOT_DIR/scripts/list_sample_elfs.sh"
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

assert_report_has_no_generic_fallbacks() {
  local report_file="$1"
  local sample_name="$2"

  local patterns=(
    "R_[A-Z0-9]+_UNKNOWN_[0-9]+"
    "R_MACHINE_[0-9]+_[0-9]+"
    "DT_PROC_0x"
    "DT_ADDRTAG_0x"
    "DT_VALTAG_0x"
    "DT_VERSIONTAG_0x"
    "NOTE_0x[0-9A-Fa-f]+"
    "NT_[A-Z0-9]+_0x[0-9A-Fa-f]+"
  )

  for pattern in "${patterns[@]}"; do
    if rg -q "$pattern" "$report_file"; then
      echo "Found generic fallback marker in $sample_name: pattern '$pattern'" >&2
      return 1
    fi
  done
}

echo "[1/7] Build"
dotnet build "$PROJECT_FILE" /clp:ErrorsOnly /m:1 /nodeReuse:false /p:UseSharedCompilation=false >/dev/null

echo "[2/7] Strict header validation rejects invalid variants"
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

echo "[3/7] Compat mode accepts legacy header variants"
run_expect_success "$strict_invalid" "compat-ei-version.txt" "--compat-header-validation"
run_expect_success "$strict_invalid_2" "compat-e-version.txt" "--compat-header-validation"
run_expect_success "$strict_invalid_3" "compat-ei-pad.txt" "--compat-header-validation"
run_expect_success "$strict_invalid_4" "compat-ph-meta.txt" "--compat-header-validation"
run_expect_success "$strict_invalid_5" "compat-sh-meta.txt" "--compat-header-validation"

echo "[4/7] Deterministic mutation smoke matrix"
for i in $(seq 0 63); do
  mutated="$TEMP_DIR/mut-$i.bin"
  cp "$SAMPLES_DIR/busybox" "$mutated"
  # Mutate deterministic offsets in ELF ident/header and nearby metadata region.
  offset=$(( (i * 173) % 4096 ))
  value=$(( (i * 13 + 17) % 256 ))
  printf "\\$(printf '%03o' "$value")" | dd of="$mutated" bs=1 seek="$offset" conv=notrunc >/dev/null 2>&1

  # Either success or controlled parser failure are acceptable for fuzz-like input.
  dotnet run --no-build --project "$PROJECT_FILE" -- \
    --file "$mutated" \
    --output "mut-$i.txt" \
    --output-path "$TEMP_DIR" \
    --deterministic >/dev/null 2>&1 || true
done

echo "[5/7] Extended sample corpus avoids generic fallback markers"
while IFS= read -r sample_name; do
  run_expect_success "$SAMPLES_DIR/$sample_name" "scan-$sample_name.txt"
  assert_report_has_no_generic_fallbacks "$TEMP_DIR/scan-$sample_name.txt" "$sample_name"
done < <("$LIST_ELFS_SCRIPT")

echo "[6/7] Truncation negatives across key architectures"
for sample_name in busybox nano hello_x86_64 hello_arm64 hello_s390x hello_mips64; do
  sample_path="$SAMPLES_DIR/$sample_name"
  [[ -f "$sample_path" ]] || continue

  for size in 16 32 48; do
    truncated="$TEMP_DIR/truncated-$sample_name-$size.bin"
    cp "$sample_path" "$truncated"
    truncate -s "$size" "$truncated"
    run_expect_failure "$truncated" "truncated-$sample_name-$size.txt"
  done
done

echo "[7/7] Strict parser validates section-string-index consistency"
strict_invalid_6="$TEMP_DIR/invalid-shstrndx.bin"
cp "$SAMPLES_DIR/hello_x86_64" "$strict_invalid_6"
printf '\x02\x00' | dd of="$strict_invalid_6" bs=1 seek=60 conv=notrunc >/dev/null 2>&1
printf '\x02\x00' | dd of="$strict_invalid_6" bs=1 seek=62 conv=notrunc >/dev/null 2>&1
run_expect_failure "$strict_invalid_6" "strict-invalid-6.txt"
run_expect_success "$strict_invalid_6" "compat-shstrndx.txt" "--compat-header-validation"

echo "P0 conformance matrix successful"
