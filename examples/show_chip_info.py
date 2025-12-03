#!/usr/bin/env python3
"""
TROPIC01 Chip Information Example

This example shows how to read TROPIC01's chip ID and firmware versions:

1. Boot to application mode and read firmware versions (RISC-V and SPECT)
2. Reboot to maintenance mode (Startup Mode)
3. Read bootloader version and firmware bank headers
4. Read chip ID
5. Reboot back to application mode

Note: Reading firmware bank headers requires the chip to be in Startup Mode
(maintenance reboot). Firmware versions can be read in Application Mode.

Usage:
    python examples/show_chip_info.py --port /dev/ttyACM0

Maps to: lt_ex_show_chip_id_and_fwver.c from libtropic C library
"""

import argparse
import logging
import sys

from libtropic import Tropic01
from libtropic.enums import StartupMode, FirmwareBank

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def format_version(version) -> str:
    """Format FirmwareVersion object as X.Y.Z (+.W)"""
    return f"{version.major:02X}.{version.minor:02X}.{version.patch:02X} (+ .{version.build:02X})"


def format_packed_version(packed: int) -> str:
    """Format packed version integer as X.Y.Z (+.W)"""
    build = (packed >> 0) & 0xFF
    patch = (packed >> 8) & 0xFF
    minor = (packed >> 16) & 0xFF
    major = (packed >> 24) & 0xFF
    return f"{major:02X}.{minor:02X}.{patch:02X} (+ .{build:02X})"


def print_firmware_header(header, bank_name: str) -> None:
    """Print firmware header information."""
    log.info("  %s:", bank_name)
    log.info("    Version: %s", format_packed_version(header.version))
    log.info("    Size: %d bytes", header.size)
    log.info("    Git hash: 0x%s", header.git_hash.hex())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TROPIC01 Chip Information Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--port",
        default="/dev/ttyACM0",
        help="Serial port for USB dongle (default: /dev/ttyACM0)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("=" * 65)
    log.info("==== TROPIC01 Show Chip ID and Firmware Versions Example ====")
    log.info("=" * 65)

    try:
        with Tropic01(args.port) as device:
            log.info("Device initialized")

            # First, ensure we're in Application Mode to read FW versions
            log.info("")
            log.info("Sending reboot request (to Application Mode)")
            device.reboot(StartupMode.REBOOT)
            log.info("OK")

            # Read RISC-V firmware version (Application FW)
            log.info("")
            log.info("Reading RISC-V FW version")
            riscv_ver = device.get_riscv_firmware_version()
            log.info("OK")
            log.info("RISC-V FW version: %s", format_version(riscv_ver))

            # Read SPECT firmware version
            log.info("")
            log.info("Reading SPECT FW version")
            spect_ver = device.get_spect_firmware_version()
            log.info("OK")
            log.info("SPECT FW version: %s", format_version(spect_ver))

            # Reboot to Startup Mode (maintenance) to read bootloader and headers
            log.info("")
            log.info("Sending maintenance reboot request (to check bootloader and FW bank headers)")
            device.reboot(StartupMode.MAINTENANCE_REBOOT)
            log.info("OK")

            # Read bootloader version (shown as RISC-V version in Startup Mode)
            log.info("")
            log.info("Reading RISC-V bootloader version")
            bootloader_ver = device.get_riscv_firmware_version()
            log.info("OK")
            # Bootloader version has bit 7 set in major byte, mask it out
            log.info(
                "RISC-V bootloader version: %02X.%02X.%02X (+ .%02X)",
                bootloader_ver.major & 0x7F,
                bootloader_ver.minor,
                bootloader_ver.patch,
                bootloader_ver.build,
            )

            # Read firmware bank headers
            log.info("")
            log.info("Reading and printing headers of all 4 FW banks:")

            header_fw1 = device.get_firmware_header(FirmwareBank.FW1)
            print_firmware_header(header_fw1, "FW1 (RISC-V Bank 1)")

            header_fw2 = device.get_firmware_header(FirmwareBank.FW2)
            print_firmware_header(header_fw2, "FW2 (RISC-V Bank 2)")

            header_spect1 = device.get_firmware_header(FirmwareBank.SPECT1)
            print_firmware_header(header_spect1, "SPECT1 (SPECT Bank 1)")

            header_spect2 = device.get_firmware_header(FirmwareBank.SPECT2)
            print_firmware_header(header_spect2, "SPECT2 (SPECT Bank 2)")

            # Read chip ID
            log.info("")
            log.info("Reading Chip ID:")
            chip_id = device.get_chip_id()
            # Use the built-in __str__ formatter for full chip ID info
            for line in str(chip_id).split('\n'):
                log.info(line)

            # Reboot back to Application Mode
            log.info("")
            log.info("Sending reboot request")
            device.reboot(StartupMode.REBOOT)
            log.info("OK, TROPIC01 is executing Application FW now")

        log.info("")
        log.info("Device deinitialized")
        return 0

    except Exception as e:
        log.error("Error: %s", e)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
