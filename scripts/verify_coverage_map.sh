#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
README_FILE="$ROOT_DIR/README.md"
START_MARKER="<!-- COVERAGE_MAP_START -->"
END_MARKER="<!-- COVERAGE_MAP_END -->"

generated_file="$(mktemp)"
readme_block_file="$(mktemp)"
trap 'rm -f "$generated_file" "$readme_block_file"' EXIT

"$ROOT_DIR/scripts/generate_coverage_map.sh" >"$generated_file"

awk -v start="$START_MARKER" -v end="$END_MARKER" '
$0 == start {
	in_block = 1
	next
}
$0 == end {
	in_block = 0
	next
}
in_block {
	print
}
' "$README_FILE" >"$readme_block_file"

if ! diff -u "$readme_block_file" "$generated_file"; then
	echo "Coverage map in README is out of date. Run: scripts/generate_coverage_map.sh --write-readme" >&2
	exit 1
fi

echo "Coverage map is up-to-date"
