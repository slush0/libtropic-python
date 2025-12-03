#!/usr/bin/env bash
#
# Run integration tests via native Linux SPI transport.
# Requires TROPIC01 hardware connected via SPI (e.g., Raspberry Pi).
#
# These tests modify device state but changes can be reversed/cleaned up.
#
# Usage:
#   ./run_integration_tests_SPI.sh                    # Use defaults
#   LIBTROPIC_CS_PIN=7 ./run_integration_tests_SPI.sh # Override CS pin
#
# Environment Variables (with defaults):
#   LIBTROPIC_SPI_DEVICE   - SPI device path (default: /dev/spidev0.0)
#   LIBTROPIC_SPI_SPEED_HZ - SPI clock speed in Hz (default: 1000000)
#   LIBTROPIC_GPIO_CHIP    - GPIO chip device (default: /dev/gpiochip0)
#   LIBTROPIC_CS_PIN       - GPIO pin for chip select (default: 8)
#   LIBTROPIC_INT_PIN      - GPIO pin for interrupt (optional)
#   LIBTROPIC_KEY_CONFIG   - Key config: "engineering" or "hwwallet" (default: engineering)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# =============================================================================
# SPI Transport Configuration
# =============================================================================
export LIBTROPIC_TRANSPORT="spi"

# SPI device path (default: /dev/spidev0.0)
export LIBTROPIC_SPI_DEVICE="${LIBTROPIC_SPI_DEVICE:-/dev/spidev0.0}"

# SPI clock speed in Hz (default: 1 MHz)
export LIBTROPIC_SPI_SPEED_HZ="${LIBTROPIC_SPI_SPEED_HZ:-1000000}"

# GPIO chip device (default: /dev/gpiochip0)
export LIBTROPIC_GPIO_CHIP="${LIBTROPIC_GPIO_CHIP:-/dev/gpiochip0}"

# GPIO pin for chip select (default: 8)
export LIBTROPIC_CS_PIN="${LIBTROPIC_CS_PIN:-8}"

# GPIO pin for interrupt (optional - uncomment to enable)
# export LIBTROPIC_INT_PIN="${LIBTROPIC_INT_PIN:-25}"

# =============================================================================
# Test Configuration
# =============================================================================

# Enable destructive tests (modify device state, but reversible)
export LIBTROPIC_RUN_DESTRUCTIVE=1

# Key configuration (default: engineering)
# Options: "engineering" (slot 0) or "hwwallet" (slot 1)
export LIBTROPIC_KEY_CONFIG="${LIBTROPIC_KEY_CONFIG:-engineering}"

# =============================================================================
# Run Tests
# =============================================================================

echo "=== Running Integration Tests via SPI ==="
echo ""
echo "Transport: SPI"
echo "  SPI Device:  ${LIBTROPIC_SPI_DEVICE}"
echo "  SPI Speed:   ${LIBTROPIC_SPI_SPEED_HZ} Hz"
echo "  GPIO Chip:   ${LIBTROPIC_GPIO_CHIP}"
echo "  CS Pin:      ${LIBTROPIC_CS_PIN}"
if [ -n "${LIBTROPIC_INT_PIN:-}" ]; then
    echo "  INT Pin:     ${LIBTROPIC_INT_PIN}"
else
    echo "  INT Pin:     (not configured)"
fi
echo ""
echo "Key Config: ${LIBTROPIC_KEY_CONFIG}"
echo ""
echo "These tests modify device state (ECC keys, memory slots, counters)"
echo "but all changes can be reversed or cleaned up."
echo ""

# Run functional tests with destructive enabled, but NOT irreversible
# This will skip tests marked @pytest.mark.irreversible
python -m pytest \
    tests/functional/ \
    -v \
    -m "not irreversible" \
    "$@"

echo ""
echo "=== Integration Tests (SPI) Complete ==="
