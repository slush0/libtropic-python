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

    # Maximum data size per slot (depends on FW version, use max)
    DATA_SIZE_MAX = 475

    def write(self, slot: int, data: bytes) -> None:
        """
        Write data to memory slot.

        Writes arbitrary data to a slot in the user partition of R-Memory.
        The slot must be empty; use erase() first if overwriting.

        Args:
            slot: Slot index (0-511)
            data: Data bytes to store (1-444 bytes)

        Raises:
            NoSessionError: If no secure session is active
            SlotNotEmptyError: If slot already contains data
            SlotExpiredError: If flash slot has expired
            ParamError: If slot is invalid or data size out of range
            UnauthorizedError: If operation not permitted by UAP config
            HardwareError: If write operation fails

        Maps to: lt_r_mem_data_write()
        """
        from .._protocol.constants import L3_CMD_R_MEM_DATA_WRITE
        from ..enums import ReturnCode
        from ..exceptions import ParamError

        if slot < self.SLOT_MIN or slot > self.SLOT_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be {self.SLOT_MIN}-{self.SLOT_MAX}, got {slot}"
            )

        if len(data) < 1 or len(data) > self.DATA_SIZE_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Data must be 1-{self.DATA_SIZE_MAX} bytes, got {len(data)}"
            )

        # Build command: slot(2B LE) + padding(1B) + data(variable)
        cmd_data = bytearray(3 + len(data))
        cmd_data[0] = slot & 0xFF
        cmd_data[1] = (slot >> 8) & 0xFF
        cmd_data[2] = 0  # padding
        cmd_data[3:] = data

        # Send command - response is empty (just result code)
        self._device._send_l3_command(L3_CMD_R_MEM_DATA_WRITE, bytes(cmd_data))

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
        from .._protocol.constants import L3_CMD_R_MEM_DATA_READ
        from ..enums import ReturnCode
        from ..exceptions import ParamError

        if slot < self.SLOT_MIN or slot > self.SLOT_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be {self.SLOT_MIN}-{self.SLOT_MAX}, got {slot}"
            )

        # Build command: slot(2B LE)
        cmd_data = bytes([slot & 0xFF, (slot >> 8) & 0xFF])

        # Send command and get response
        # Response: padding(3B) + data(variable)
        response = self._device._send_l3_command(L3_CMD_R_MEM_DATA_READ, cmd_data)

        # Skip 3 bytes of padding
        data = response[3:]

        # Check if slot is empty (device returns OK but with no data)
        # This matches C library behavior in lt_r_mem_data_read()
        if len(data) == 0:
            from ..exceptions import SlotEmptyError
            raise SlotEmptyError(
                ReturnCode.L3_R_MEM_DATA_READ_SLOT_EMPTY,
                "Slot is empty"
            )

        return data

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
        from .._protocol.constants import L3_CMD_R_MEM_DATA_ERASE
        from ..enums import ReturnCode
        from ..exceptions import ParamError

        if slot < self.SLOT_MIN or slot > self.SLOT_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be {self.SLOT_MIN}-{self.SLOT_MAX}, got {slot}"
            )

        # Build command: slot(2B LE)
        cmd_data = bytes([slot & 0xFF, (slot >> 8) & 0xFF])

        # Send command - response is empty (just result code)
        self._device._send_l3_command(L3_CMD_R_MEM_DATA_ERASE, cmd_data)

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
