#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[1/8] Unit tests (dotnet test)"
"$ROOT_DIR/scripts/run_unit_tests.sh"

echo "[2/8] Conformance matrix (P0)"
"$ROOT_DIR/scripts/run_p0_conformance_matrix.sh"

echo "[3/8] Conformance matrix (P2)"
"$ROOT_DIR/scripts/run_p2_conformance_matrix.sh"

echo "[4/8] Parser hardening matrix (P3)"
"$ROOT_DIR/scripts/run_p3_test_matrix.sh"

echo "[5/8] Advanced feature matrix (P4)"
"$ROOT_DIR/scripts/run_p4_test_matrix.sh"

echo "[6/8] Differential checks vs reference tools"
"$ROOT_DIR/scripts/run_differential_checks.sh"

echo "[7/8] Coverage map drift check"
"$ROOT_DIR/scripts/verify_coverage_map.sh"

echo "[8/8] GAP metrics regression check"
"$ROOT_DIR/scripts/verify_gap_metrics.sh"

echo "CI gate successful"
