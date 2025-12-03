"""
Bundled firmware binaries for TROPIC01.

This module provides pre-signed firmware binaries for updating TROPIC01
secure elements. These binaries are signed by Tropic Square and are
compatible with ACAB silicon (bootloader v2.0.1).

Available firmware:
    - CPU_FW_V2_0_0: Application firmware v2.0.0
    - SPECT_FW_V1_0_0: SPECT coprocessor firmware v1.0.0

Usage:
    from libtropic import Tropic01, StartupMode, DeviceMode
    from libtropic.firmware_data import CPU_FW_V2_0_0

    with Tropic01("/dev/ttyACM0") as device:
        # Reboot to maintenance mode
        if device.mode != DeviceMode.MAINTENANCE:
            device.reboot(StartupMode.MAINTENANCE_REBOOT)

        # Update CPU firmware
        device.firmware.update(CPU_FW_V2_0_0)

        # Reboot to application mode
        device.reboot(StartupMode.REBOOT)

Note:
    These firmware files are for ACAB silicon (bootloader v2.0.1) only.
    This library does not support firmware updates for older ABAB silicon.
"""

from importlib.resources import files, as_file
from pathlib import Path


def _load_firmware(filename: str) -> bytes:
    """Load firmware binary from package resources."""
    # Try importlib.resources first (Python 3.9+)
    try:
        fw_files = files("libtropic.firmware_files")
        with as_file(fw_files.joinpath(filename)) as fw_path:
            return fw_path.read_bytes()
    except (TypeError, FileNotFoundError):
        pass

    # Fallback to direct file path
    module_dir = Path(__file__).parent
    fw_path = module_dir / "firmware_files" / filename
    if fw_path.exists():
        return fw_path.read_bytes()

    raise FileNotFoundError(
        f"Firmware file not found: {filename}. "
        "Ensure the libtropic package is properly installed."
    )


# Lazy-loaded firmware binaries
_cpu_fw_v2_0_0: bytes | None = None
_spect_fw_v1_0_0: bytes | None = None


def _get_cpu_fw_v2_0_0() -> bytes:
    """Get CPU firmware v2.0.0 (lazy loaded)."""
    global _cpu_fw_v2_0_0
    if _cpu_fw_v2_0_0 is None:
        _cpu_fw_v2_0_0 = _load_firmware("fw_v2.0.0.hex32_signed_chunks.bin")
    return _cpu_fw_v2_0_0


def _get_spect_fw_v1_0_0() -> bytes:
    """Get SPECT firmware v1.0.0 (lazy loaded)."""
    global _spect_fw_v1_0_0
    if _spect_fw_v1_0_0 is None:
        _spect_fw_v1_0_0 = _load_firmware("spect_app-v1.0.0_signed_chunks.bin")
    return _spect_fw_v1_0_0


class _LazyFirmware:
    """Lazy-loading wrapper for firmware data."""

    def __init__(self, loader):
        self._loader = loader
        self._data: bytes | None = None

    def __bytes__(self) -> bytes:
        if self._data is None:
            self._data = self._loader()
        return self._data

    def __len__(self) -> int:
        return len(bytes(self))

    def __getitem__(self, key):
        return bytes(self)[key]

    def __repr__(self) -> str:
        return f"<LazyFirmware: {len(self)} bytes>"


# Public firmware constants (lazy-loaded)
CPU_FW_V2_0_0 = _LazyFirmware(_get_cpu_fw_v2_0_0)
"""CPU (RISC-V) application firmware v2.0.0 for ACAB silicon."""

SPECT_FW_V1_0_0 = _LazyFirmware(_get_spect_fw_v1_0_0)
"""SPECT coprocessor firmware v1.0.0 for ACAB silicon."""


# Version information
CPU_FW_VERSION = "2.0.0"
SPECT_FW_VERSION = "1.0.0"
BOOTLOADER_VERSION = "2.0.1"
SILICON_REVISION = "ACAB"


__all__ = [
    "CPU_FW_V2_0_0",
    "SPECT_FW_V1_0_0",
    "CPU_FW_VERSION",
    "SPECT_FW_VERSION",
    "BOOTLOADER_VERSION",
    "SILICON_REVISION",
]
