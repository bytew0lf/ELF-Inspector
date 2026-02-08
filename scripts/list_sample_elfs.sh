#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLES_DIR="$ROOT_DIR/samples"

find "$SAMPLES_DIR" -mindepth 1 -maxdepth 1 -type f -print0 \
  | while IFS= read -r -d '' file; do
      magic="$(dd if="$file" bs=1 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')"
      if [[ "$magic" == "7f454c46" ]]; then
        basename "$file"
      fi
    done \
  | sort
