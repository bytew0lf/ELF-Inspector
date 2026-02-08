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

extract_header_field() {
	local key="$1"
	local input="$2"
	awk -F: -v key="$key" '
		$0 ~ "^[[:space:]]*" key ":" {
			value = substr($0, index($0, ":") + 1)
			gsub(/^[[:space:]]+/, "", value)
			print value
			exit
		}
	' <<<"$input"
}

extract_first_token() {
	local value="$1"
	awk '{
		if (NF > 0) {
			print $1
		}
	}' <<<"$value"
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

	ref_class_raw="$(extract_first_token "$(extract_header_field "Class" "$header_output")")"
	ref_data_raw="$(extract_header_field "Data" "$header_output")"
	ref_entry="$(extract_first_token "$(extract_header_field "Entry point address" "$header_output")")"
	ref_segments="$(extract_first_token "$(extract_header_field "Number of program headers" "$header_output")")"
	ref_sections="$(extract_first_token "$(extract_header_field "Number of section headers" "$header_output")")"

	ref_class="$(normalize_class "$ref_class_raw")"
	ref_endian="$(normalize_endianness "$ref_data_raw")"

	report_class="$(awk -F': *' '/^Class:/{print $2; exit}' "$report_file")"
	report_endian="$(awk -F': *' '/^Endianness:/{print $2; exit}' "$report_file")"
	report_entry="$(awk -F': *' '/^EntryPoint:/{print $2; exit}' "$report_file")"
	report_segments="$(awk -F': *' '/^Segments:/{print $2; exit}' "$report_file")"
	report_sections="$(awk -F': *' '/^Sections:/{print $2; exit}' "$report_file")"

	ref_dynamic_output="$("$ref_tool" -d "$sample_file" 2>/dev/null || true)"
	if grep -qi "no dynamic section" <<<"$ref_dynamic_output"; then
		ref_dynamic_count="0"
	else
		ref_dynamic_count="$(grep -cE '^[[:space:]]*0x' <<<"$ref_dynamic_output" || true)"
	fi
	report_dynamic_count="$(awk -F': *' '/^Dynamic Entries:/{print $2; exit}' "$report_file")"

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
