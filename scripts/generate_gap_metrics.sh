#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="${1:-$ROOT_DIR/samples/golden}"

if [[ ! -d "$REPORT_DIR" ]]; then
	echo "Report directory not found: $REPORT_DIR" >&2
	exit 1
fi

if ! compgen -G "$REPORT_DIR/report-*.txt" >/dev/null; then
	echo "No golden reports found in: $REPORT_DIR" >&2
	exit 1
fi

count_pattern() {
	local pattern="$1"
	local count

	if command -v rg >/dev/null 2>&1; then
		count="$( (rg -o --no-messages -g 'report-*.txt' "$pattern" "$REPORT_DIR" || true) | wc -l | tr -d '[:space:]' )"
	else
		count=0
		while IFS= read -r -d '' report_file; do
			local matches lines
			matches="$(grep -E -o -- "$pattern" "$report_file" || true)"
			if [[ -z "$matches" ]]; then
				continue
			fi

			lines="$(printf '%s\n' "$matches" | wc -l | tr -d '[:space:]')"
			count=$((count + lines))
		done < <(find "$REPORT_DIR" -type f -name 'report-*.txt' -print0)
	fi

	echo "$count"
}

machine_fallback="$(count_pattern "EM_[0-9]+")"
osabi_fallback="$(count_pattern "ELFOSABI_[0-9]+")"
section_numeric_fallback="$(count_pattern "SHT_[0-9]+")"
segment_numeric_fallback="$(count_pattern "PT_[0-9]+")"
relocation_fallback="$(count_pattern "R_[A-Z0-9]+_UNKNOWN_[0-9]+|R_MACHINE_[0-9]+|REL_[0-9]+")"
note_fallback="$(count_pattern "NOTE_0x[0-9A-Fa-f]+|NT_[A-Z0-9]+_0x[0-9A-Fa-f]+")"
dynamic_tag_fallback="$(count_pattern "DT_0x[0-9A-Fa-f]+")"
dynamic_range_tag_fallback="$(count_pattern "DT_PROC_0x|DT_ADDRTAG_0x|DT_VALTAG_0x|DT_VERSIONTAG_0x|DT_-?[0-9]+")"
dynamic_value_fallback="$(count_pattern "processor_specific\\(tag=DT_PROC_0x|processor_specific\\(machine=.*tag=0x")"
note_descriptor_fallback="$(count_pattern "bytes=[0-9]+, preview=0x|descriptor truncated: bytes=")"

total_fallback="$((machine_fallback + osabi_fallback + section_numeric_fallback + segment_numeric_fallback + relocation_fallback + note_fallback + dynamic_tag_fallback + dynamic_range_tag_fallback + dynamic_value_fallback + note_descriptor_fallback))"

cat <<EOF
machine_fallback=$machine_fallback
osabi_fallback=$osabi_fallback
section_numeric_fallback=$section_numeric_fallback
segment_numeric_fallback=$segment_numeric_fallback
relocation_fallback=$relocation_fallback
note_fallback=$note_fallback
dynamic_tag_fallback=$dynamic_tag_fallback
dynamic_range_tag_fallback=$dynamic_range_tag_fallback
dynamic_value_fallback=$dynamic_value_fallback
note_descriptor_fallback=$note_descriptor_fallback
total_fallback=$total_fallback
EOF
