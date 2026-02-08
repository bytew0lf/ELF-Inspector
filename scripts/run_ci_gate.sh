#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[1/5] Unit tests (dotnet test)"
"$ROOT_DIR/scripts/run_unit_tests.sh"

echo "[2/5] Conformance matrix (P0)"
"$ROOT_DIR/scripts/run_p0_conformance_matrix.sh"

echo "[3/5] Parser hardening matrix (P3)"
"$ROOT_DIR/scripts/run_p3_test_matrix.sh"

echo "[4/5] Advanced feature matrix (P4)"
"$ROOT_DIR/scripts/run_p4_test_matrix.sh"

echo "[5/5] Coverage map drift check"
"$ROOT_DIR/scripts/verify_coverage_map.sh"

echo "CI gate successful"
