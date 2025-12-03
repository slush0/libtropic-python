"""
Hardware random number generation for libtropic.

Provides access to TROPIC01's hardware RNG.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .device import Tropic01


class RandomGenerator:
    """
    Hardware random number generator access.

    Provides cryptographically secure random bytes from TROPIC01's
    hardware random number generator.

    Example:
        with Tropic01("/dev/ttyACM0") as device:
            device.start_session(priv_key, pub_key, slot=0)

            # Get 32 random bytes
            random_data = device.random.get_bytes(32)
            print(f"Random: {random_data.hex()}")
    """

    # Maximum bytes per request
    MAX_BYTES = 255

    def __init__(self, device: 'Tropic01'):
        """
        Initialize random generator module.

        Args:
            device: Parent Tropic01 device instance
        """
        self._device = device

    def get_bytes(self, count: int) -> bytes:
        """
        Get random bytes from hardware RNG.

        Args:
            count: Number of random bytes to generate (1-255)

        Returns:
            Requested number of random bytes

        Raises:
            NoSessionError: If no secure session is active
            ParamError: If count is out of range (1-255)
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_random_value_get()
        """
        from ._protocol.constants import L3_CMD_RANDOM_VALUE_GET
        from .enums import ReturnCode
        from .exceptions import ParamError

        # Validate count (1-255)
        if count < 1 or count > self.MAX_BYTES:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Count must be 1-{self.MAX_BYTES}, got {count}"
            )

        # Build command data: n_bytes (1 byte)
        cmd_data = bytes([count])

        # Send L3 command and get response
        # Response format: padding(3) + random_data(count)
        response_data = self._device._send_l3_command(L3_CMD_RANDOM_VALUE_GET, cmd_data)

        # Skip 3 bytes of padding, return random data
        random_data = response_data[3:3 + count]

        return random_data

    def __call__(self, count: int) -> bytes:
        """
        Convenience call syntax for get_bytes().

        Allows: device.random(32) instead of device.random.get_bytes(32)
        """
        return self.get_bytes(count)
