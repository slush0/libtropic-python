"""
Hardware random number generation for libtropic.

Provides access to TROPIC01's hardware RNG.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..device import Tropic01


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
        raise NotImplementedError()

    def __call__(self, count: int) -> bytes:
        """
        Convenience call syntax for get_bytes().

        Allows: device.random(32) instead of device.random.get_bytes(32)
        """
        return self.get_bytes(count)
