#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_FILE="$ROOT_DIR/ELF-Inspector.csproj"
SAMPLES_LIST_SCRIPT="$ROOT_DIR/scripts/list_sample_elfs.sh"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

detect_reference_tool() {
	if [[ -n "${READELF_TOOL:-}" ]]; then
		if command -v "$READELF_TOOL" >/dev/null 2>&1; then
			echo "$READELF_TOOL"
			return 0
		fi
		echo "Configured READELF_TOOL not found: $READELF_TOOL" >&2
		return 1
	fi

	for candidate in readelf eu-readelf llvm-readelf; do
		if command -v "$candidate" >/dev/null 2>&1; then
			echo "$candidate"
			return 0
		fi
	done

	return 1
}

normalize_endianness() {
	local readelf_data_line="$1"
	local lowered
	lowered="$(echo "$readelf_data_line" | tr '[:upper:]' '[:lower:]')"
	if [[ "$lowered" == *"little endian"* ]]; then
		echo "LittleEndian"
	elif [[ "$lowered" == *"big endian"* ]]; then
		echo "BigEndian"
	else
		echo ""
	fi
}

normalize_class() {
	local class_value="$1"
	case "$class_value" in
		ELF64) echo "Elf64" ;;
		ELF32) echo "Elf32" ;;
		*) echo "" ;;
	esac
}

extract_single_value() {
	local regex="$1"
	local input="$2"
	sed -nE "s/${regex}/\\1/p" <<<"$input" | head -n1
}

assert_equal() {
	local sample="$1"
	local field="$2"
	local expected="$3"
	local actual="$4"
	if [[ -z "$expected" || -z "$actual" ]]; then
		echo "[$sample] $field: unable to extract comparison values (expected='$expected', actual='$actual')" >&2
		return 1
	fi
	if [[ "$expected" != "$actual" ]]; then
		echo "[$sample] $field mismatch: expected '$expected', got '$actual'" >&2
		return 1
	fi
	return 0
}

if ! ref_tool="$(detect_reference_tool)"; then
	echo "Differential checks skipped: no reference tool found (readelf/eu-readelf/llvm-readelf)." >&2
	exit 0
fi

samples=()
while IFS= read -r sample_name; do
	samples+=("$sample_name")
done < <("$SAMPLES_LIST_SCRIPT")
if [[ "${#samples[@]}" -eq 0 ]]; then
	echo "No ELF samples found for differential checks." >&2
	exit 1
fi

echo "Using reference tool: $ref_tool"
echo "Differential sample count: ${#samples[@]}"

dotnet build "$PROJECT_FILE" /clp:ErrorsOnly /m:1 /nodeReuse:false /p:UseSharedCompilation=false >/dev/null

failures=0
for sample in "${samples[@]}"; do
	sample_file="$ROOT_DIR/samples/$sample"
	report_file="$TEMP_DIR/report-$sample.txt"

	dotnet run --no-build --project "$PROJECT_FILE" -- \
		--file "$sample_file" \
		--output "report-$sample.txt" \
		--output-path "$TEMP_DIR" \
		--deterministic >/dev/null

	header_output="$("$ref_tool" -h "$sample_file" 2>/dev/null || true)"
	if [[ -z "$header_output" ]]; then
		echo "[$sample] unable to read ELF header via $ref_tool" >&2
		failures=$((failures + 1))
		continue
	fi

	ref_class_raw="$(extract_single_value '^[[:space:]]*Class:[[:space:]]*(ELF[0-9][0-9]).*' "$header_output")"
	ref_data_raw="$(extract_single_value '^[[:space:]]*Data:[[:space:]]*(.*)$' "$header_output")"
	ref_entry="$(extract_single_value '^[[:space:]]*Entry point address:[[:space:]]*(0x[0-9A-Fa-f]+).*$' "$header_output")"
	ref_segments="$(extract_single_value '^[[:space:]]*Number of program headers:[[:space:]]*([0-9]+).*$' "$header_output")"
	ref_sections="$(extract_single_value '^[[:space:]]*Number of section headers:[[:space:]]*([0-9]+).*$' "$header_output")"

	ref_class="$(normalize_class "$ref_class_raw")"
	ref_endian="$(normalize_endianness "$ref_data_raw")"

	report_class="$(sed -n 's/^Class:[[:space:]]*\\(Elf[0-9][0-9]\\)$/\1/p' "$report_file" | head -n1)"
	report_endian="$(sed -n 's/^Endianness:[[:space:]]*\\(.*\\)$/\1/p' "$report_file" | head -n1)"
	report_entry="$(sed -n 's/^EntryPoint:[[:space:]]*\\(0x[0-9A-Fa-f]\\+\\)$/\1/p' "$report_file" | head -n1)"
	report_segments="$(sed -n 's/^Segments:[[:space:]]*\\([0-9]\\+\\)$/\1/p' "$report_file" | head -n1)"
	report_sections="$(sed -n 's/^Sections:[[:space:]]*\\([0-9]\\+\\)$/\1/p' "$report_file" | head -n1)"

	ref_dynamic_output="$("$ref_tool" -d "$sample_file" 2>/dev/null || true)"
	if grep -qi "no dynamic section" <<<"$ref_dynamic_output"; then
		ref_dynamic_count="0"
	else
		ref_dynamic_count="$(grep -cE '^[[:space:]]*0x' <<<"$ref_dynamic_output" || true)"
	fi
	report_dynamic_count="$(sed -n 's/^Dynamic Entries:[[:space:]]*\\([0-9]\\+\\)$/\1/p' "$report_file" | head -n1)"

	ref_entry_normalized="$(echo "$ref_entry" | tr '[:upper:]' '[:lower:]')"
	report_entry_normalized="$(echo "$report_entry" | tr '[:upper:]' '[:lower:]')"

	assert_equal "$sample" "Class" "$ref_class" "$report_class" || failures=$((failures + 1))
	assert_equal "$sample" "Endianness" "$ref_endian" "$report_endian" || failures=$((failures + 1))
	assert_equal "$sample" "EntryPoint" "$ref_entry_normalized" "$report_entry_normalized" || failures=$((failures + 1))
	assert_equal "$sample" "ProgramHeaderCount" "$ref_segments" "$report_segments" || failures=$((failures + 1))
	assert_equal "$sample" "SectionHeaderCount" "$ref_sections" "$report_sections" || failures=$((failures + 1))
	assert_equal "$sample" "DynamicEntryCount" "$ref_dynamic_count" "$report_dynamic_count" || failures=$((failures + 1))
done

if [[ "$failures" -gt 0 ]]; then
	echo "Differential checks failed: $failures mismatch(es)." >&2
	exit 1
fi

echo "Differential checks successful"
