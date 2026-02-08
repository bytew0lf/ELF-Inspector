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

  dotnet run --no-build --project "$PROJECT_FILE" -- \
    --file "$elf_file" \
    --output "$output_name" \
    --output-path "$TEMP_DIR" \
    --deterministic >/dev/null

  local report_file="$TEMP_DIR/$output_name"
  [[ -f "$report_file" ]] || { echo "Missing report file: $report_file" >&2; return 1; }

  rg -q "^Header$" "$report_file"
  rg -q "^Relocations \(resolved\)$" "$report_file"
  rg -q "^Notes$" "$report_file"
}

run_expect_failure() {
  local elf_file="$1"
  local output_name="$2"

  if dotnet run --no-build --project "$PROJECT_FILE" -- \
    --file "$elf_file" \
    --output "$output_name" \
    --output-path "$TEMP_DIR" \
    --deterministic >/dev/null 2>&1; then
    echo "Expected failure, but command succeeded for: $elf_file" >&2
    return 1
  fi
}

echo "[1/4] Build"
dotnet build "$PROJECT_FILE" /clp:ErrorsOnly >/dev/null

echo "[2/4] Positive matrix"
run_expect_success "$SAMPLES_DIR/busybox" "matrix-busybox.txt"
run_expect_success "$SAMPLES_DIR/nano" "matrix-nano.txt"

echo "[3/4] Golden verification"
"$ROOT_DIR/scripts/verify_golden_reports.sh" >/dev/null

echo "[4/4] Negative matrix"
short_file="$TEMP_DIR/short.bin"
printf '\x7FELF' > "$short_file"
run_expect_failure "$short_file" "short-report.txt"

truncated_file="$TEMP_DIR/truncated.bin"
head -c 256 "$SAMPLES_DIR/nano" > "$truncated_file"
run_expect_failure "$truncated_file" "truncated-report.txt"

random_file="$TEMP_DIR/random.bin"
head -c 1024 /dev/urandom > "$random_file"
run_expect_failure "$random_file" "random-report.txt"

echo "P3 test matrix successful"
