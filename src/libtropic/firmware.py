"""
Firmware update operations for libtropic.

Provides firmware update functionality for TROPIC01 (maintenance mode only).
Implements the ACAB silicon authenticated firmware update protocol.
"""

from typing import TYPE_CHECKING

from .enums import DeviceMode, ReturnCode
from .exceptions import ParamError, TropicError
from .types import MUTABLE_FW_UPDATE_SIZE_MAX

if TYPE_CHECKING:
    from .device import Tropic01


# ACAB firmware update header size (first part of signed firmware file)
# Format: req_len(1) + signature(64) + hash(32) + type(2) + padding(1)
#         + header_version(1) + version(4)
ACAB_FW_HEADER_SIZE = 105

# Maximum firmware size for ACAB silicon
MAX_FW_SIZE = MUTABLE_FW_UPDATE_SIZE_MAX  # 30720 bytes


class FirmwareUpdater:
    """
    Firmware update operations for ACAB silicon.

    TROPIC01 supports updating its mutable firmware (Application FW and
    SPECT coprocessor FW) while in maintenance mode using authenticated
    signed firmware files.

    The ACAB silicon uses an authenticated update protocol:
    1. Send signed header with signature and hash
    2. Send firmware data in authenticated chunks
    3. Chip verifies signature and applies update to appropriate bank

    IMPORTANT: Firmware updates can brick the device if done incorrectly.
    Only use official signed firmware files from Tropic Square.

    Example:
        # Load signed firmware binary (user's responsibility)
        with open("fw_v2.0.0.hex32_signed_chunks.bin", "rb") as f:
            firmware_data = f.read()

        with Tropic01("/dev/ttyACM0") as device:
            # Must be in maintenance mode
            if device.mode != DeviceMode.MAINTENANCE:
                device.reboot(StartupMode.MAINTENANCE_REBOOT)

            # Update firmware (chip manages banks automatically)
            device.firmware.update(firmware_data)

            # Reboot to new firmware
            device.reboot(StartupMode.REBOOT)
    """

    # Maximum firmware size
    MAX_SIZE = MAX_FW_SIZE

    def __init__(self, device: 'Tropic01'):
        """
        Initialize firmware updater module.

        Args:
            device: Parent Tropic01 device instance
        """
        self._device = device

    def _ensure_maintenance_mode(self) -> None:
        """Ensure device is in maintenance mode."""
        if self._device.mode != DeviceMode.MAINTENANCE:
            raise TropicError(
                ReturnCode.FAIL,
                "Firmware operations require maintenance mode. "
                "Call device.reboot(StartupMode.MAINTENANCE_REBOOT) first."
            )

    def update(self, firmware_data: bytes) -> None:
        """
        Update firmware using ACAB authenticated protocol.

        Sends the signed firmware file to the device. The firmware file
        must be a properly signed binary from Tropic Square with the
        `*_signed_chunks.bin` format.

        The chip automatically manages firmware banks - you don't need
        to specify which bank to use.

        Args:
            firmware_data: Complete signed firmware binary
                          (e.g., fw_v2.0.0.hex32_signed_chunks.bin)

        Raises:
            TropicError: If device is not in maintenance mode
            ParamError: If firmware data is invalid or too large

        Note:
            Use official signed firmware binaries from Tropic Square.

        Maps to: lt_do_mutable_fw_update() [ACAB]
        """
        from ._protocol.constants import (
            L2_MUTABLE_FW_UPDATE_DATA_REQ_ID,
            L2_MUTABLE_FW_UPDATE_REQ_ID,
        )

        self._ensure_maintenance_mode()

        # Validate firmware data
        if len(firmware_data) == 0:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                "Firmware data cannot be empty"
            )
        if len(firmware_data) <= ACAB_FW_HEADER_SIZE:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Firmware data too small: {len(firmware_data)} bytes "
                f"(must be > {ACAB_FW_HEADER_SIZE} bytes for ACAB format)"
            )
        if len(firmware_data) > self.MAX_SIZE:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Firmware data too large: {len(firmware_data)} bytes "
                f"(max {self.MAX_SIZE} bytes)"
            )

        # Get L2 layer
        l2 = self._device._ensure_open()

        # =====================================================================
        # Phase 1: Send authenticated header (Mutable_FW_Update request)
        # =====================================================================
        # Header format in firmware file (first 105 bytes):
        #   req_len(1) + signature(64) + hash(32) + type(2) + padding(1) +
        #   header_version(1) + version(4)
        #
        # L2 request format (104 bytes, without req_len prefix):
        #   signature(64) + hash(32) + type(2) + padding(1) +
        #   header_version(1) + version(4)

        # Extract header components (skip first byte which is req_len)
        header_data = firmware_data[1:ACAB_FW_HEADER_SIZE]

        # Send Mutable_FW_Update request with header
        l2.send_receive(L2_MUTABLE_FW_UPDATE_REQ_ID, header_data)

        # =====================================================================
        # Phase 2: Send firmware data chunks (Mutable_FW_Update_Data requests)
        # =====================================================================
        # Data chunks start after the header
        # Each chunk in the file is prefixed with a length byte
        # File format: [chunk_len_byte][chunk_data...]
        # L2 format: [req_id][req_len][chunk_data...][crc]
        # The L2 layer sets req_len automatically, so we only send chunk_data

        chunk_index = ACAB_FW_HEADER_SIZE
        fw_size = len(firmware_data)

        while chunk_index < fw_size:
            # Read chunk length from file (this is req_len value)
            chunk_payload_len = firmware_data[chunk_index]

            # Validate chunk boundaries
            if chunk_index + 1 + chunk_payload_len > fw_size:
                raise ParamError(
                    ReturnCode.PARAM_ERR,
                    f"Invalid firmware chunk at offset {chunk_index}: "
                    f"chunk extends beyond file end"
                )

            # Extract chunk data (skip the length byte - L2 layer adds req_len)
            chunk_data = firmware_data[chunk_index + 1:chunk_index + 1 + chunk_payload_len]

            # Send Mutable_FW_Update_Data request
            l2.send_receive(L2_MUTABLE_FW_UPDATE_DATA_REQ_ID, chunk_data)

            # Move to next chunk (length byte + payload)
            chunk_index += 1 + chunk_payload_len
