#!/usr/bin/env bash
#
# Run integration tests (non-irreversible).
# Requires TROPIC01 hardware connected.
#
# These tests modify device state but changes can be reversed/cleaned up.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"


cd "$PROJECT_ROOT"

echo "=== Running Integration Tests (Non-Irreversible) ==="
echo ""
echo "Device: ${LIBTROPIC_DEVICE:-/dev/ttyACM0}"
echo ""
echo "These tests modify device state (ECC keys, memory slots, counters)"
echo "but all changes can be reversed or cleaned up."
echo ""

# Run functional tests with destructive enabled, but NOT irreversible
# This will skip tests marked @pytest.mark.irreversible
export LIBTROPIC_RUN_DESTRUCTIVE=1

# FIXME This is for device already modified by hwwallet example from libtropic
export LIBTROPIC_KEY_CONFIG="hwwallet"

python -m pytest \
    tests/functional/ \
    -v \
    -m "not irreversible" \
    "$@"

echo ""
echo "=== Integration Tests Complete ==="
