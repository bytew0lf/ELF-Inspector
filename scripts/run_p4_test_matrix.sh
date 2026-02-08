#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_FILE="$ROOT_DIR/ELF-Inspector.csproj"
SAMPLES_DIR="$ROOT_DIR/samples"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

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

rg -q "SHT_RELR" "$busybox_report"
rg -q "\\[RELR\\]" "$busybox_report"
rg -q "DT_FLAGS \\(30\\) = 0x[0-9A-F]+ -> .*DF_BIND_NOW" "$nano_report"
rg -q "DT_FLAGS_1 \\(1879048187\\) = 0x[0-9A-F]+ -> .*DF_1_" "$nano_report"

relr_total="$(rg -c "\\[RELR\\]" "$busybox_report")"
relr_unknown="$(rg -c "\\[RELR\\].*section=\\(unknown\\)" "$busybox_report" || true)"
relr_unknown="${relr_unknown:-0}"
if [[ "$relr_total" -gt 0 && "$relr_total" -eq "$relr_unknown" ]]; then
  echo "RELR relocations were parsed, but none were mapped to a concrete section." >&2
  exit 1
fi

echo "P4 test matrix successful"
