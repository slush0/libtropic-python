"""
Firmware update operations for libtropic.

Provides firmware update functionality for TROPIC01 (maintenance mode only).
"""

from typing import TYPE_CHECKING

from .enums import FirmwareBank
from .types import (
    MUTABLE_FW_UPDATE_SIZE_MAX_ABAB,
    MUTABLE_FW_UPDATE_SIZE_MAX_ACAB,
)

if TYPE_CHECKING:
    from .device import Tropic01


class FirmwareUpdater:
    """
    Firmware update operations.

    TROPIC01 supports updating its mutable firmware (Application FW and
    SPECT coprocessor FW) while in maintenance mode.

    The chip has two banks for each firmware type:
    - FW1/FW2: Application firmware banks
    - SPECT1/SPECT2: SPECT coprocessor firmware banks

    Firmware update process differs by silicon revision:
    - ABAB: Manual bank selection, erase then write
    - ACAB: Automatic bank management, authenticated update

    IMPORTANT: Firmware updates can brick the device if done incorrectly.
    Always ensure you have valid firmware files from Tropic Square.

    Example (ABAB silicon):
        with Tropic01("/dev/ttyACM0") as device:
            # Must be in maintenance mode
            if device.mode != DeviceMode.MAINTENANCE:
                device.reboot(StartupMode.MAINTENANCE_REBOOT)

            # Erase and update firmware
            device.firmware.erase(FirmwareBank.FW2)
            device.firmware.update(FirmwareBank.FW2, firmware_data)

            # Reboot to new firmware
            device.reboot(StartupMode.REBOOT)
    """

    # Size limits by silicon revision
    MAX_SIZE_ABAB = MUTABLE_FW_UPDATE_SIZE_MAX_ABAB
    MAX_SIZE_ACAB = MUTABLE_FW_UPDATE_SIZE_MAX_ACAB

    def __init__(self, device: 'Tropic01'):
        """
        Initialize firmware updater module.

        Args:
            device: Parent Tropic01 device instance
        """
        self._device = device

    def erase(self, bank: FirmwareBank | int) -> None:
        """
        Erase firmware bank (ABAB silicon only).

        Erases the specified firmware bank in preparation for update.
        Must be called before update() on ABAB silicon.

        Args:
            bank: Firmware bank to erase (FW1, FW2, SPECT1, or SPECT2)

        Raises:
            TropicError: If device is not in maintenance mode
            ParamError: If bank is invalid

        Note:
            This function is only available on ABAB silicon revision.
            ACAB silicon handles bank management automatically.

        Maps to: lt_mutable_fw_erase() [ABAB only]
        """
        raise NotImplementedError()

    def update(
        self,
        bank: FirmwareBank | int,
        firmware_data: bytes
    ) -> None:
        """
        Update firmware in specified bank.

        Writes firmware data to the specified bank. On ABAB silicon,
        erase() must be called first. On ACAB silicon, the chip handles
        bank management automatically.

        Args:
            bank: Target firmware bank (FW1, FW2, SPECT1, or SPECT2)
                  On ACAB silicon, this parameter is ignored.
            firmware_data: Firmware binary data

        Raises:
            TropicError: If device is not in maintenance mode
            ParamError: If bank is invalid or data exceeds size limit

        Note:
            Maximum firmware size differs by silicon:
            - ABAB: 25,600 bytes
            - ACAB: 30,720 bytes

        Maps to: lt_mutable_fw_update() / lt_do_mutable_fw_update()
        """
        raise NotImplementedError()

    def update_complete(
        self,
        bank: FirmwareBank | int,
        firmware_data: bytes
    ) -> None:
        """
        Perform complete firmware update (erase + write).

        Convenience method that erases the bank and writes new firmware
        in one operation. Works on both ABAB and ACAB silicon.

        Args:
            bank: Target firmware bank (FW1, FW2, SPECT1, or SPECT2)
                  On ACAB silicon, this parameter is ignored.
            firmware_data: Firmware binary data

        Raises:
            TropicError: If device is not in maintenance mode
            ParamError: If bank is invalid or data exceeds size limit

        Maps to: lt_do_mutable_fw_update()
        """
        raise NotImplementedError()
