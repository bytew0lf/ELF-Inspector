#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_FILE="$ROOT_DIR/ELF-Inspector.csproj"
SAMPLES_DIR="$ROOT_DIR/samples"
GOLDEN_DIR="$SAMPLES_DIR/golden"
LIST_ELFS_SCRIPT="$ROOT_DIR/scripts/list_sample_elfs.sh"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

elf_names=()
while IFS= read -r elf_name; do
  elf_names+=("$elf_name")
done < <("$LIST_ELFS_SCRIPT")
if [[ "${#elf_names[@]}" -eq 0 ]]; then
  echo "No ELF samples found in: $SAMPLES_DIR" >&2
  exit 1
fi

dotnet build "$PROJECT_FILE" /clp:ErrorsOnly >/dev/null

for elf_name in "${elf_names[@]}"; do
  elf_file="$SAMPLES_DIR/$elf_name"
  expected_file="$GOLDEN_DIR/report-$elf_name.txt"
  actual_file="$TEMP_DIR/report-$elf_name.txt"

  if [[ ! -f "$elf_file" ]]; then
    echo "Missing ELF sample: $elf_file" >&2
    exit 1
  fi

  if [[ ! -f "$expected_file" ]]; then
    echo "Missing golden report: $expected_file" >&2
    exit 1
  fi

  dotnet run --no-build --project "$PROJECT_FILE" -- \
    --file "$elf_file" \
    --output "report-$elf_name.txt" \
    --output-path "$TEMP_DIR" \
    --deterministic >/dev/null

  if ! diff -u "$expected_file" "$actual_file"; then
    echo "Golden report mismatch for $elf_name" >&2
    exit 1
  fi
done

echo "Golden report verification successful"
