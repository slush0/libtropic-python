"""
R-Memory data storage operations for libtropic.

Provides access to TROPIC01's user data partition in R-Memory.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..device import Tropic01


class DataMemory:
    """
    User data storage in R-Memory.

    Provides 512 slots (0-511) for storing arbitrary data in the secure
    element's rewritable memory. Each slot can store variable-length data.

    Example:
        with Tropic01("/dev/ttyACM0") as device:
            device.start_session(priv_key, pub_key, slot=0)

            # Write data to slot
            device.memory.write(slot=100, data=b"secret data")

            # Read data back
            data = device.memory.read(slot=100)

            # Erase slot
            device.memory.erase(slot=100)
    """

    # Slot limits
    SLOT_MIN = 0
    SLOT_MAX = 511

    def __init__(self, device: 'Tropic01'):
        """
        Initialize data memory module.

        Args:
            device: Parent Tropic01 device instance
        """
        self._device = device

    def write(self, slot: int, data: bytes) -> None:
        """
        Write data to memory slot.

        Writes arbitrary data to a slot in the user partition of R-Memory.
        The slot must be empty; use erase() first if overwriting.

        Args:
            slot: Slot index (0-511)
            data: Data bytes to store

        Raises:
            NoSessionError: If no secure session is active
            SlotNotEmptyError: If slot already contains data
            SlotExpiredError: If flash slot has expired
            ParamError: If slot is invalid or data size out of range
            UnauthorizedError: If operation not permitted by UAP config
            HardwareError: If write operation fails

        Maps to: lt_r_mem_data_write()
        """
        raise NotImplementedError()

    def read(self, slot: int) -> bytes:
        """
        Read data from memory slot.

        Reads data previously stored in a slot.

        Args:
            slot: Slot index (0-511)

        Returns:
            Data bytes stored in slot

        Raises:
            NoSessionError: If no secure session is active
            SlotEmptyError: If slot is empty
            ParamError: If slot is invalid
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_r_mem_data_read()
        """
        raise NotImplementedError()

    def erase(self, slot: int) -> None:
        """
        Erase data from memory slot.

        Permanently erases data in a slot, making it available for new writes.

        Args:
            slot: Slot index (0-511)

        Raises:
            NoSessionError: If no secure session is active
            ParamError: If slot is invalid
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_r_mem_data_erase()
        """
        raise NotImplementedError()

    def __getitem__(self, slot: int) -> bytes:
        """
        Allow dict-like read access: data = device.memory[100]
        """
        return self.read(slot)

    def __setitem__(self, slot: int, data: bytes) -> None:
        """
        Allow dict-like write access: device.memory[100] = b"data"

        Note: This will fail if slot is not empty. Use erase() first.
        """
        self.write(slot, data)

    def __delitem__(self, slot: int) -> None:
        """
        Allow dict-like delete: del device.memory[100]
        """
        self.erase(slot)
