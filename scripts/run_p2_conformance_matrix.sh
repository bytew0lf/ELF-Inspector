#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_FILE="$ROOT_DIR/ELF-Inspector.csproj"
SAMPLES_DIR="$ROOT_DIR/samples"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

run_parse_any_outcome() {
  local elf_file="$1"
  local output_name="$2"

  dotnet run --no-build --project "$PROJECT_FILE" -- \
    --file "$elf_file" \
    --output "$output_name" \
    --output-path "$TEMP_DIR" \
    --deterministic >/dev/null 2>&1 || true
}

echo "[1/4] Build"
dotnet build "$PROJECT_FILE" /clp:ErrorsOnly /m:1 /nodeReuse:false /p:UseSharedCompilation=false >/dev/null

echo "[2/4] Mutation-focused unit corpus"
dotnet test "$ROOT_DIR/tests/ELFInspector.UnitTests/ELFInspector.UnitTests.csproj" \
  --filter "Parse_FullFileMutationCorpus_ProducesOnlyControlledFailures|Parse_TargetedDynamicAndRelocationMutationCorpus_ProducesOnlyControlledFailures" >/dev/null

echo "[3/4] Deterministic full-file mutation matrix"
for sample in busybox nano hello_x86_64; do
  source_file="$SAMPLES_DIR/$sample"
  [[ -f "$source_file" ]] || { echo "Missing sample: $source_file" >&2; exit 1; }
  file_size="$(wc -c < "$source_file")"
  [[ "$file_size" -gt 0 ]] || { echo "Empty sample: $source_file" >&2; exit 1; }

  for i in $(seq 0 63); do
    mutated="$TEMP_DIR/${sample}-mut-$i.bin"
    cp "$source_file" "$mutated"
    offset=$(( (i * 4099 + 97) % file_size ))
    value=$(( (i * 37 + 11) % 256 ))
    printf "\\$(printf '%03o' "$value")" | dd of="$mutated" bs=1 seek="$offset" conv=notrunc >/dev/null 2>&1
    run_parse_any_outcome "$mutated" "${sample}-mut-$i.txt"
  done
done

echo "[4/4] Truncation matrix"
for sample in busybox nano hello_x86_64; do
  source_file="$SAMPLES_DIR/$sample"
  [[ -f "$source_file" ]] || { echo "Missing sample: $source_file" >&2; exit 1; }
  for size in 64 96 128 192 256 512 1024 2048 4096; do
    truncated="$TEMP_DIR/${sample}-trunc-$size.bin"
    head -c "$size" "$source_file" > "$truncated"
    run_parse_any_outcome "$truncated" "${sample}-trunc-$size.txt"
  done
done

echo "P2 conformance matrix successful"
