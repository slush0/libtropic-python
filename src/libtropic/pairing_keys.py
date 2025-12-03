"""
Pairing key operations for libtropic.

Manages the X25519 pairing keys used for secure session establishment.
"""

from typing import TYPE_CHECKING

from .enums import PairingKeySlot
from .types import X25519_KEY_LEN

if TYPE_CHECKING:
    from .device import Tropic01


class PairingKeys:
    """
    Pairing key management.

    TROPIC01 supports 4 pairing key slots (0-3) for establishing secure
    sessions. Each slot stores a host's X25519 public key (SHxPub).

    Pairing keys reside in I-Memory, which has a narrower operating
    temperature range (-20°C to 85°C). Operations outside this range
    may fail silently on older firmware (pre-v2.0.0).

    Example:
        with Tropic01("/dev/ttyACM0") as device:
            device.start_session(priv_key, pub_key, slot=0)

            # Write a new pairing key to slot 1
            new_pub_key = generate_x25519_keypair()[1]
            device.pairing_keys.write(slot=1, public_key=new_pub_key)

            # Read back
            stored_key = device.pairing_keys.read(slot=1)

            # Invalidate (permanent)
            device.pairing_keys.invalidate(slot=1)
    """

    # Slot limits
    SLOT_MIN = 0
    SLOT_MAX = 3

    # Key size
    KEY_SIZE = X25519_KEY_LEN  # 32 bytes

    def __init__(self, device: 'Tropic01'):
        """
        Initialize pairing keys module.

        Args:
            device: Parent Tropic01 device instance
        """
        self._device = device

    def write(
        self,
        slot: int | PairingKeySlot,
        public_key: bytes
    ) -> None:
        """
        Write pairing public key to slot.

        Stores an X25519 public key in the specified pairing key slot.
        This key will be used for future secure session establishment.

        WARNING: Pairing keys reside in I-Memory with narrower temperature
        range (-20°C to 85°C).

        Args:
            slot: Pairing key slot index (0-3)
            public_key: 32-byte X25519 public key

        Raises:
            NoSessionError: If no secure session is active
            ParamError: If slot is invalid or key is wrong size
            UnauthorizedError: If operation not permitted by UAP config
            HardwareError: If write operation fails

        Maps to: lt_pairing_key_write()
        """
        from ._protocol.constants import L3_CMD_PAIRING_KEY_WRITE
        from .enums import ReturnCode
        from .exceptions import ParamError

        slot_idx = int(slot)
        if slot_idx < self.SLOT_MIN or slot_idx > self.SLOT_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be {self.SLOT_MIN}-{self.SLOT_MAX}, got {slot_idx}"
            )

        if len(public_key) != self.KEY_SIZE:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Public key must be {self.KEY_SIZE} bytes, got {len(public_key)}"
            )

        # Build command: slot(2B LE) + padding(1B) + pubkey(32B)
        cmd_data = bytearray(35)  # 2 + 1 + 32
        cmd_data[0] = slot_idx & 0xFF
        cmd_data[1] = (slot_idx >> 8) & 0xFF
        cmd_data[2] = 0  # padding
        cmd_data[3:35] = public_key

        # Send command - response is empty (just result code)
        self._device._send_l3_command(L3_CMD_PAIRING_KEY_WRITE, bytes(cmd_data))

    def read(self, slot: int | PairingKeySlot) -> bytes:
        """
        Read pairing public key from slot.

        Args:
            slot: Pairing key slot index (0-3)

        Returns:
            32-byte X25519 public key

        Raises:
            NoSessionError: If no secure session is active
            SlotEmptyError: If slot is empty
            SlotInvalidError: If slot has been invalidated
            ParamError: If slot is invalid
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_pairing_key_read()
        """
        from ._protocol.constants import L3_CMD_PAIRING_KEY_READ
        from .enums import ReturnCode
        from .exceptions import ParamError

        slot_idx = int(slot)
        if slot_idx < self.SLOT_MIN or slot_idx > self.SLOT_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be {self.SLOT_MIN}-{self.SLOT_MAX}, got {slot_idx}"
            )

        # Build command: slot(2B LE)
        cmd_data = bytes([slot_idx & 0xFF, (slot_idx >> 8) & 0xFF])

        # Send command and get response
        # Response: padding(3B) + pubkey(32B)
        response = self._device._send_l3_command(L3_CMD_PAIRING_KEY_READ, cmd_data)

        # Skip 3 bytes padding, return public key
        return response[3:35]

    def invalidate(self, slot: int | PairingKeySlot) -> None:
        """
        Permanently invalidate pairing key slot.

        WARNING: This operation is PERMANENT. Once invalidated, the slot
        cannot be reused and will return SlotInvalidError on read.

        Pairing keys reside in I-Memory with narrower temperature range
        (-20°C to 85°C).

        Args:
            slot: Pairing key slot index (0-3)

        Raises:
            NoSessionError: If no secure session is active
            ParamError: If slot is invalid
            UnauthorizedError: If operation not permitted by UAP config
            HardwareError: If invalidation fails

        Maps to: lt_pairing_key_invalidate()
        """
        from ._protocol.constants import L3_CMD_PAIRING_KEY_INVALIDATE
        from .enums import ReturnCode
        from .exceptions import ParamError

        slot_idx = int(slot)
        if slot_idx < self.SLOT_MIN or slot_idx > self.SLOT_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be {self.SLOT_MIN}-{self.SLOT_MAX}, got {slot_idx}"
            )

        # Build command: slot(2B LE)
        cmd_data = bytes([slot_idx & 0xFF, (slot_idx >> 8) & 0xFF])

        # Send command - response is empty (just result code)
        self._device._send_l3_command(L3_CMD_PAIRING_KEY_INVALIDATE, cmd_data)

    def __getitem__(self, slot: int) -> bytes:
        """
        Allow indexed read access: key = device.pairing_keys[0]
        """
        return self.read(slot)

    def __setitem__(self, slot: int, public_key: bytes) -> None:
        """
        Allow indexed write access: device.pairing_keys[1] = new_key
        """
        self.write(slot, public_key)
