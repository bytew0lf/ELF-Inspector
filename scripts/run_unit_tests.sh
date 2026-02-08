#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_PROJECT="$ROOT_DIR/tests/ELFInspector.UnitTests/ELFInspector.UnitTests.csproj"

dotnet test "$TEST_PROJECT" --nologo
