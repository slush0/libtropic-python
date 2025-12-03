#!/usr/bin/env python3
"""
TROPIC01 Firmware Update Example

This example demonstrates how to update TROPIC01's mutable firmware:

1. Reboot to maintenance mode (Startup Mode)
2. Update RISC-V (CPU) firmware
3. Update SPECT coprocessor firmware
4. Show updated firmware headers
5. Reboot to application mode

IMPORTANT: Firmware updates can brick the device if done incorrectly.
Only use official signed firmware files from Tropic Square.

Download firmware binaries from:
https://github.com/tropicsquare/libtropic/tree/master/TROPIC01_fw_update_files

Choose the correct directory based on your bootloader version:
  - boot_v_1_0_1/  -> for bootloader v1.0.1 (ABAB silicon)
  - boot_v_2_0_1/  -> for bootloader v2.0.1 (ACAB silicon, uses *_signed_chunks.bin)

Example files for ACAB silicon (bootloader v2.0.1):
  - fw_v2.0.0.hex32_signed_chunks.bin (RISC-V/CPU firmware)
  - spect_app-v1.0.0_signed_chunks.bin (SPECT firmware)

Usage:
    python examples/fw_update.py --port /dev/ttyACM0 \\
        --cpu fw_v2.0.0.hex32_signed_chunks.bin \\
        --spect spect_app-v1.0.0_signed_chunks.bin

Maps to: lt_ex_fw_update.c from libtropic C library
"""

import argparse
import logging
import sys
from pathlib import Path

from libtropic import Tropic01
from libtropic.enums import StartupMode, FirmwareBank, DeviceMode

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
        description="TROPIC01 Firmware Update Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--port",
        default="/dev/ttyACM0",
        help="Serial port for USB dongle (default: /dev/ttyACM0)",
    )
    parser.add_argument(
        "--cpu",
        type=Path,
        required=True,
        help="Path to RISC-V/CPU firmware binary (e.g., fw_v2.0.0.hex32_signed_chunks.bin)",
    )
    parser.add_argument(
        "--spect",
        type=Path,
        required=True,
        help="Path to SPECT firmware binary (e.g., spect_app-v1.0.0_signed_chunks.bin)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate firmware files exist
    if not args.cpu.exists():
        log.error("CPU firmware file not found: %s", args.cpu)
        log.error("Download from: https://github.com/tropicsquare/libtropic/tree/master/TROPIC01_fw_update_files")
        return 1
    if not args.spect.exists():
        log.error("SPECT firmware file not found: %s", args.spect)
        log.error("Download from: https://github.com/tropicsquare/libtropic/tree/master/TROPIC01_fw_update_files")
        return 1

    # Load firmware files
    log.info("Loading firmware files...")
    cpu_firmware = args.cpu.read_bytes()
    spect_firmware = args.spect.read_bytes()
    log.info("  CPU firmware: %s (%d bytes)", args.cpu.name, len(cpu_firmware))
    log.info("  SPECT firmware: %s (%d bytes)", args.spect.name, len(spect_firmware))

    log.info("=" * 40)
    log.info("==== TROPIC01 FW Update Example ====")
    log.info("=" * 40)

    try:
        with Tropic01(args.port) as device:
            log.info("Device initialized")

            # Step 1: Reboot to maintenance mode
            log.info("")
            log.info("1. Sending maintenance reboot request")
            device.reboot(StartupMode.MAINTENANCE_REBOOT)
            log.info("OK - Device is now in Startup Mode")

            # Verify we're in maintenance mode
            if device.mode != DeviceMode.MAINTENANCE:
                log.error("Device did not enter maintenance mode!")
                return 1

            # Step 2: Update RISC-V (CPU) firmware
            log.info("")
            log.info("2. Updating RISC-V (CPU) firmware")
            log.info("   File: %s", args.cpu.name)
            device.firmware.update(cpu_firmware)
            log.info("OK - CPU firmware updated")

            # Step 3: Update SPECT firmware
            log.info("")
            log.info("3. Updating SPECT firmware")
            log.info("   File: %s", args.spect.name)
            device.firmware.update(spect_firmware)
            log.info("OK - SPECT firmware updated")

            # Step 4: Print firmware headers
            log.info("")
            log.info("4. Successfully updated firmware banks:")

            header_fw1 = device.get_firmware_header(FirmwareBank.FW1)
            print_firmware_header(header_fw1, "FW1 (RISC-V Bank 1)")

            header_fw2 = device.get_firmware_header(FirmwareBank.FW2)
            print_firmware_header(header_fw2, "FW2 (RISC-V Bank 2)")

            header_spect1 = device.get_firmware_header(FirmwareBank.SPECT1)
            print_firmware_header(header_spect1, "SPECT1 (SPECT Bank 1)")

            header_spect2 = device.get_firmware_header(FirmwareBank.SPECT2)
            print_firmware_header(header_spect2, "SPECT2 (SPECT Bank 2)")

            # Step 5: Reboot to application mode
            log.info("")
            log.info("5. Sending reboot request")
            device.reboot(StartupMode.REBOOT)
            log.info("OK - TROPIC01 is executing Application FW now")

            # Read and display new firmware versions
            log.info("")
            log.info("Current firmware versions:")
            riscv_ver = device.get_riscv_firmware_version()
            log.info("  RISC-V FW version: %s", format_version(riscv_ver))

            spect_ver = device.get_spect_firmware_version()
            log.info("  SPECT FW version: %s", format_version(spect_ver))

        log.info("")
        log.info("Device deinitialized - Firmware update complete!")
        return 0

    except Exception as e:
        log.error("Error: %s", e)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
