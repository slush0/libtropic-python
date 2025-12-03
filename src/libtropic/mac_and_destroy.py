"""
MAC-and-Destroy operations for libtropic.

Provides secure PIN/password verification with hardware-enforced attempt limits.
"""

from typing import TYPE_CHECKING

from .enums import MacAndDestroySlot
from .types import MAC_AND_DESTROY_DATA_SIZE

if TYPE_CHECKING:
    from .device import Tropic01


class MacAndDestroy:
    """
    MAC-and-Destroy secure verification operations.

    MAC-and-Destroy (M&D) provides hardware-backed secure verification with
    limited attempts. Each M&D slot contains a secret that gets destroyed
    after a configured number of failed attempts.

    This is typically used for PIN verification where:
    - Correct PIN → secret released, attempts reset
    - Wrong PIN → attempt consumed, secret closer to destruction
    - Too many wrong attempts → secret permanently destroyed

    TROPIC01 provides 128 M&D slots (0-127).

    The M&D protocol works as follows:
    1. Host sends challenge data to chip
    2. Chip computes HMAC using slot's secret
    3. Chip returns result to host
    4. Host verifies result locally

    See the TROPIC01 M&D Application Note for full protocol details.

    Example:
        with Tropic01("/dev/ttyACM0") as device:
            device.start_session(priv_key, pub_key, slot=0)

            # Execute M&D operation
            challenge = compute_challenge(pin_hash)
            response = device.mac_and_destroy.execute(slot=0, data=challenge)

            # Verify response locally
            if verify_response(response, expected):
                print("PIN correct!")
            else:
                print("PIN incorrect, attempt consumed")
    """

    # Slot limits
    SLOT_MIN = 0
    SLOT_MAX = 127

    # Data sizes
    DATA_SIZE = MAC_AND_DESTROY_DATA_SIZE  # 32 bytes

    # Maximum rounds possible
    MAX_ROUNDS = 128

    def __init__(self, device: 'Tropic01'):
        """
        Initialize MAC-and-Destroy module.

        Args:
            device: Parent Tropic01 device instance
        """
        self._device = device

    def execute(
        self,
        slot: int | MacAndDestroySlot,
        data: bytes
    ) -> bytes:
        """
        Execute MAC-and-Destroy operation on slot.

        Sends challenge data to the chip and receives the MAC result.
        This operation consumes one attempt from the slot's allowance
        unless the verification succeeds.

        Args:
            slot: M&D slot index (0-127)
            data: 32-byte challenge/input data

        Returns:
            32-byte MAC result from chip

        Raises:
            NoSessionError: If no secure session is active
            ParamError: If slot is invalid or data is wrong size
            UnauthorizedError: If operation not permitted by UAP config

        Note:
            This is just the chip-side operation. Complete M&D verification
            requires additional host-side logic. See the TROPIC01 M&D
            Application Note for the full protocol.

        Maps to: lt_mac_and_destroy()
        """
        from ._protocol.constants import L3_CMD_MAC_AND_DESTROY
        from .enums import ReturnCode
        from .exceptions import ParamError

        slot_idx = int(slot)
        if slot_idx < self.SLOT_MIN or slot_idx > self.SLOT_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be {self.SLOT_MIN}-{self.SLOT_MAX}, got {slot_idx}"
            )

        if len(data) != self.DATA_SIZE:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Data must be {self.DATA_SIZE} bytes, got {len(data)}"
            )

        # Build command: slot(2B LE) + padding(1B) + data_in(32B)
        cmd_data = bytearray(35)  # 2 + 1 + 32
        cmd_data[0] = slot_idx & 0xFF
        cmd_data[1] = (slot_idx >> 8) & 0xFF
        cmd_data[2] = 0  # padding
        cmd_data[3:35] = data

        # Send command and get response
        # Response: padding(3B) + data_out(32B)
        response = self._device._send_l3_command(L3_CMD_MAC_AND_DESTROY, bytes(cmd_data))

        # Skip 3 bytes padding, return MAC result
        return response[3:35]

    def __call__(
        self,
        slot: int | MacAndDestroySlot,
        data: bytes
    ) -> bytes:
        """
        Convenience call syntax for execute().

        Allows: result = device.mac_and_destroy(slot=0, data=challenge)
        """
        return self.execute(slot, data)
