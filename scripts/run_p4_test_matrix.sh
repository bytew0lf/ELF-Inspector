#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_FILE="$ROOT_DIR/ELF-Inspector.csproj"
SAMPLES_DIR="$ROOT_DIR/samples"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

contains_pattern() {
  local pattern="$1"
  local file="$2"

  if command -v rg >/dev/null 2>&1; then
    rg -q "$pattern" "$file"
  else
    grep -Eq "$pattern" "$file"
  fi
}

count_pattern() {
  local pattern="$1"
  local file="$2"
  local count

  if command -v rg >/dev/null 2>&1; then
    count="$(rg -c "$pattern" "$file" || true)"
    echo "${count:-0}"
  else
    grep -Ec "$pattern" "$file" || true
  fi
}

dotnet build "$PROJECT_FILE" /clp:ErrorsOnly >/dev/null

for elf_name in busybox nano; do
  elf_file="$SAMPLES_DIR/$elf_name"
  report_file="$TEMP_DIR/report-$elf_name.txt"

  if [[ ! -f "$elf_file" ]]; then
    echo "Missing ELF sample: $elf_file" >&2
    exit 1
  fi

  dotnet run --project "$PROJECT_FILE" -- \
    --file "$elf_file" \
    --output "report-$elf_name.txt" \
    --output-path "$TEMP_DIR" \
    --deterministic >/dev/null

  if [[ ! -f "$report_file" ]]; then
    echo "Missing generated report: $report_file" >&2
    exit 1
  fi
done

busybox_report="$TEMP_DIR/report-busybox.txt"
nano_report="$TEMP_DIR/report-nano.txt"

contains_pattern "SHT_RELR" "$busybox_report"
contains_pattern "\\[RELR\\]" "$busybox_report"
contains_pattern "DT_FLAGS \\(30\\) = 0x[0-9A-F]+ -> .*DF_BIND_NOW" "$nano_report"
contains_pattern "DT_FLAGS_1 \\(1879048187\\) = 0x[0-9A-F]+ -> .*DF_1_" "$nano_report"

relr_total="$(count_pattern "\\[RELR\\]" "$busybox_report")"
relr_unknown="$(count_pattern "\\[RELR\\].*section=\\(unknown\\)" "$busybox_report")"
relr_unknown="${relr_unknown:-0}"
if [[ "$relr_total" -gt 0 && "$relr_total" -eq "$relr_unknown" ]]; then
  echo "RELR relocations were parsed, but none were mapped to a concrete section." >&2
  exit 1
fi

echo "P4 test matrix successful"
