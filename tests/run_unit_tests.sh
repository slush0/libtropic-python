#!/usr/bin/env bash
#
# Run standard unit tests (including CAL tests).
# No hardware required.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "=== Running Unit Tests (including CAL) ==="
echo ""

# Run unit tests (tests/unit/ directory including cal/)
# Also run test_imports.py which is a basic unit test
python -m pytest \
    tests/unit/ \
    tests/test_imports.py \
    -v \
    "$@"

echo ""
echo "=== Unit Tests Complete ==="
