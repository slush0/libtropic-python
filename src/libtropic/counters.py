"""
Monotonic counter operations for libtropic.

Provides access to TROPIC01's hardware monotonic counters.
"""

from typing import TYPE_CHECKING, Union

from .enums import McounterIndex
from .types import MCOUNTER_VALUE_MAX

if TYPE_CHECKING:
    from .device import Tropic01


class MonotonicCounters:
    """
    Hardware monotonic counter operations.

    TROPIC01 provides 16 monotonic counters (0-15) that can only count down.
    Each counter:
    - Must be initialized before use
    - Starts at a value up to 0xFFFFFFFE
    - Decrements by 1 on each update
    - Cannot be reset once initialized (only via chip reset)

    Counters are useful for rate limiting, enforcing maximum usage counts,
    or implementing secure boot counters.

    Example:
        with Tropic01("/dev/ttyACM0") as device:
            device.start_session(priv_key, pub_key, slot=0)

            # Initialize counter 0 with 100 tries
            device.counters.init(index=0, value=100)

            # Decrement counter
            device.counters.update(index=0)

            # Read current value
            value = device.counters.get(index=0)
            print(f"Remaining: {value}")

            # Shorthand access
            print(f"Counter 0: {device.counters[0]}")
    """

    # Counter limits
    INDEX_MIN = 0
    INDEX_MAX = 15
    VALUE_MAX = MCOUNTER_VALUE_MAX

    def __init__(self, device: 'Tropic01'):
        """
        Initialize counters module.

        Args:
            device: Parent Tropic01 device instance
        """
        self._device = device

    def init(
        self,
        index: Union[int, McounterIndex],
        value: int = 0
    ) -> None:
        """
        Initialize monotonic counter with starting value.

        Sets the initial value for a counter. Counter values count DOWN
        from the initial value toward zero.

        Args:
            index: Counter index (0-15)
            value: Initial value (0 to 0xFFFFFFFE)

        Raises:
            NoSessionError: If no secure session is active
            ParamError: If index or value is out of range
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_mcounter_init()
        """
        raise NotImplementedError()

    def update(self, index: Union[int, McounterIndex]) -> None:
        """
        Decrement monotonic counter.

        Decreases the counter value by 1. Fails if counter is at 0
        or not initialized.

        Args:
            index: Counter index (0-15)

        Raises:
            NoSessionError: If no secure session is active
            CounterInvalidError: If counter is at 0 or not initialized
            ParamError: If index is out of range
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_mcounter_update()
        """
        raise NotImplementedError()

    def get(self, index: Union[int, McounterIndex]) -> int:
        """
        Get current counter value.

        Args:
            index: Counter index (0-15)

        Returns:
            Current counter value (0 to 0xFFFFFFFE)

        Raises:
            NoSessionError: If no secure session is active
            CounterInvalidError: If counter is not initialized
            ParamError: If index is out of range
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_mcounter_get()
        """
        raise NotImplementedError()

    def __getitem__(self, index: int) -> int:
        """
        Allow indexed read access: value = device.counters[0]
        """
        return self.get(index)

    def decrement(self, index: Union[int, McounterIndex]) -> int:
        """
        Decrement counter and return new value.

        Convenience method that updates the counter and returns
        the new value in one call.

        Args:
            index: Counter index (0-15)

        Returns:
            Counter value after decrement
        """
        self.update(index)
        return self.get(index)
