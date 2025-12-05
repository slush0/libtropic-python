#!/usr/bin/env python3
"""
Helper script to upload firmware to TROPIC01 using libtropic-python.

Loads firmware binaries from libtropic-upstream and uploads them to the device.

Usage:
    python upload_firmware.py cpu                    # Upload CPU firmware v2.0.0
    python upload_firmware.py spect                  # Upload SPECT firmware v1.0.0
    python upload_firmware.py cpu --version 1.0.1    # Upload CPU firmware v1.0.1
    python upload_firmware.py --device /dev/ttyACM1  # Use different device
"""

import argparse
import sys
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent / "src"))

from libtropic import Tropic01, DeviceMode, StartupMode


# Firmware paths in libtropic-upstream
UPSTREAM_DIR = Path(__file__).parent / "libtropic-upstream"
FW_BASE = UPSTREAM_DIR / "TROPIC01_fw_update_files" / "boot_v_2_0_1"

FIRMWARE_FILES = {
    "cpu": {
        "1.0.0": FW_BASE / "fw_v_1_0_0" / "fw_v1.0.0.hex32_signed_chunks.bin",
        "1.0.1": FW_BASE / "fw_v_1_0_1" / "fw_v1.0.1.hex32_signed_chunks.bin",
        "2.0.0": FW_BASE / "fw_v_2_0_0" / "fw_v2.0.0.hex32_signed_chunks.bin",
    },
    "spect": {
        "1.0.0": FW_BASE / "fw_v_2_0_0" / "spect_app-v1.0.0_signed_chunks.bin",
    },
}

DEFAULT_VERSIONS = {
    "cpu": "2.0.0",
    "spect": "1.0.0",
}


def load_firmware(fw_type: str, version: str) -> bytes:
    """Load firmware binary from libtropic-upstream."""
    if fw_type not in FIRMWARE_FILES:
        raise ValueError(f"Unknown firmware type: {fw_type}")

    versions = FIRMWARE_FILES[fw_type]
    if version not in versions:
        available = ", ".join(versions.keys())
        raise ValueError(f"Unknown {fw_type} version: {version}. Available: {available}")

    fw_path = versions[version]
    if not fw_path.exists():
        raise FileNotFoundError(f"Firmware file not found: {fw_path}")

    print(f"Loading firmware: {fw_path}")
    return fw_path.read_bytes()


def upload_firmware(device_path: str, fw_type: str, version: str, skip_reboot: bool = False) -> None:
    """Upload firmware to device."""
    # Load firmware
    firmware_data = load_firmware(fw_type, version)
    print(f"Loaded {len(firmware_data)} bytes")

    with Tropic01(device_path) as device:
        print(f"Connected to device at {device_path}")
        print(f"Current mode: {device.mode}")

        # Switch to maintenance mode if needed
        if device.mode != DeviceMode.MAINTENANCE:
            print("Rebooting to maintenance mode...")
            device.reboot(StartupMode.MAINTENANCE_REBOOT)
            print(f"Now in mode: {device.mode}")

        # Upload firmware
        print(f"Uploading {fw_type.upper()} firmware v{version}...")
        device.firmware.update(firmware_data)
        print("Upload complete!")

        # Reboot to application mode
        if not skip_reboot:
            print("Rebooting to application mode...")
            device.reboot(StartupMode.REBOOT)
            print(f"Final mode: {device.mode}")
        else:
            print("Skipping reboot (--no-reboot specified)")


def main():
    parser = argparse.ArgumentParser(
        description="Upload firmware to TROPIC01 device",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s cpu                    Upload CPU firmware v2.0.0
    %(prog)s spect                  Upload SPECT firmware v1.0.0
    %(prog)s cpu --version 1.0.1    Upload CPU firmware v1.0.1
    %(prog)s cpu -d /dev/ttyACM1    Use different device path
        """,
    )
    parser.add_argument(
        "firmware",
        nargs="?",
        choices=["cpu", "spect"],
        help="Firmware type to upload",
    )
    parser.add_argument(
        "-v", "--version",
        help="Firmware version (default: latest)",
    )
    parser.add_argument(
        "-d", "--device",
        default="/dev/ttyACM0",
        help="Device path (default: /dev/ttyACM0)",
    )
    parser.add_argument(
        "--no-reboot",
        action="store_true",
        help="Don't reboot after upload",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available firmware versions",
    )

    args = parser.parse_args()

    if args.list:
        print("Available firmware versions:")
        for fw_type, versions in FIRMWARE_FILES.items():
            print(f"\n  {fw_type.upper()}:")
            for ver, path in versions.items():
                exists = "✓" if path.exists() else "✗"
                default = " (default)" if ver == DEFAULT_VERSIONS.get(fw_type) else ""
                print(f"    {exists} v{ver}{default}")
        return

    if not args.firmware:
        parser.error("firmware type required (cpu or spect)")

    version = args.version or DEFAULT_VERSIONS.get(args.firmware)

    try:
        upload_firmware(args.device, args.firmware, version, args.no_reboot)
        print("\n✓ Firmware upload successful!")
    except FileNotFoundError as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        print("Make sure libtropic-upstream submodule is initialized:", file=sys.stderr)
        print("  git submodule update --init", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
