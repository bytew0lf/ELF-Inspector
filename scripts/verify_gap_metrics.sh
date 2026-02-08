#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THRESHOLD_FILE="$ROOT_DIR/scripts/gap_thresholds.conf"

if [[ ! -f "$THRESHOLD_FILE" ]]; then
	echo "Missing GAP threshold file: $THRESHOLD_FILE" >&2
	exit 1
fi

current_file="$(mktemp)"
trap 'rm -f "$current_file"' EXIT

"$ROOT_DIR/scripts/generate_gap_metrics.sh" >"$current_file"

failed=0
while IFS='=' read -r key max_allowed; do
	[[ -z "$key" || "${key:0:1}" == "#" ]] && continue

	current_value="$(awk -F'=' -v key="$key" '$1 == key { print $2 }' "$current_file")"
	if [[ -z "$current_value" ]]; then
		echo "Missing metric in generated output: $key" >&2
		failed=1
		continue
	fi

	if [[ ! "$current_value" =~ ^[0-9]+$ || ! "$max_allowed" =~ ^[0-9]+$ ]]; then
		echo "Non-numeric metric/threshold for '$key': value='$current_value' threshold='$max_allowed'" >&2
		failed=1
		continue
	fi

	if (( current_value > max_allowed )); then
		echo "GAP regression: $key=$current_value exceeds threshold $max_allowed" >&2
		failed=1
	fi
done <"$THRESHOLD_FILE"

if (( failed != 0 )); then
	echo "GAP metrics verification failed." >&2
	exit 1
fi

echo "GAP metrics are within thresholds"
cat "$current_file"
