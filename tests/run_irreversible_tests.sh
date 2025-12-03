#!/usr/bin/env bash
#
# Run irreversible integration tests.
# Requires TROPIC01 hardware connected.
#
# WARNING: These tests PERMANENTLY modify device state!
# - I-Config writes cannot be undone
# - Pairing key modifications may lock out the device
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "============================================================"
echo "  WARNING: IRREVERSIBLE TESTS"
echo "============================================================"
echo ""
echo "Device: ${LIBTROPIC_DEVICE:-/dev/ttyACM0}"
echo ""
echo "These tests PERMANENTLY modify device state:"
echo "  - I-Config writes (cannot be undone)"
echo "  - Pairing key modifications"
echo ""
echo "Running these tests may render your device unusable"
echo "for further testing or development!"
echo ""
echo "============================================================"
echo ""

read -p "Are you sure you want to run irreversible tests? (y/N): " response

case "$response" in
    [yY]|[yY][eE][sS])
        echo ""
        echo "=== Running Irreversible Integration Tests ==="
        echo ""

        # Enable both destructive and irreversible tests
        export LIBTROPIC_RUN_DESTRUCTIVE=1
        export LIBTROPIC_RUN_IRREVERSIBLE=1

        python -m pytest \
            tests/functional/ \
            -v \
            -m "irreversible" \
            "$@"

        echo ""
        echo "=== Irreversible Tests Complete ==="
        ;;
    *)
        echo ""
        echo "Aborted. No tests were run."
        exit 0
        ;;
esac
