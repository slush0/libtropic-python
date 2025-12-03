"""
Test Monotonic Counter Init, Get, and Update L3 commands.

Mirrors: libtropic-upstream/tests/functional/lt_test_rev_mcounter.c

Tests hardware monotonic counter operations on all 16 counters (0-15).
"""

import pytest

from libtropic import CounterInvalidError, McounterIndex, Tropic01

from ..conftest import MCOUNTER_MAX, MCOUNTER_MIN


# Maximum counter value
MCOUNTER_VALUE_MAX = 0xFFFFFFFE


@pytest.mark.hardware
@pytest.mark.destructive
class TestMcounter:
    """
    Tests for Mcounter_Init, Mcounter_Get, and Mcounter_Update commands.

    Maps to: lt_test_rev_mcounter()
    """

    def test_mcounter_init_get_update_all(self, device_with_session: Tropic01) -> None:
        """
        Test initializing, getting, and updating all counters.

        For each counter:
        1. Initialize with test value
        2. Get and verify initial value
        3. Update (decrement) counter
        4. Get and verify decremented value
        """
        test_initial_value = 100

        for index in range(MCOUNTER_MIN, MCOUNTER_MAX + 1):
            # Initialize counter
            device_with_session.counters.init(index=index, value=test_initial_value)

            # Get and verify initial value
            value = device_with_session.counters.get(index)
            assert value == test_initial_value, (
                f"Counter {index}: Expected {test_initial_value}, got {value}"
            )

            # Update (decrement) counter
            device_with_session.counters.update(index)

            # Get and verify decremented value
            value = device_with_session.counters.get(index)
            assert value == test_initial_value - 1, (
                f"Counter {index}: Expected {test_initial_value - 1}, got {value}"
            )

    def test_mcounter_init_max_value(self, device_with_session: Tropic01) -> None:
        """Test initializing counter with maximum value."""
        index = 0

        # Initialize with max value
        device_with_session.counters.init(index=index, value=MCOUNTER_VALUE_MAX)

        # Verify
        value = device_with_session.counters.get(index)
        assert value == MCOUNTER_VALUE_MAX

    def test_mcounter_decrement_to_zero(self, device_with_session: Tropic01) -> None:
        """
        Test decrementing counter to zero.

        Counter at 0 should raise CounterInvalidError on update.
        """
        index = 0
        initial_value = 2

        # Initialize with small value
        device_with_session.counters.init(index=index, value=initial_value)

        # Decrement to 1
        device_with_session.counters.update(index)
        assert device_with_session.counters.get(index) == 1

        # Decrement to 0
        device_with_session.counters.update(index)
        assert device_with_session.counters.get(index) == 0

        # Further update should fail (counter at 0)
        with pytest.raises(CounterInvalidError):
            device_with_session.counters.update(index)

    def test_mcounter_init_zero(self, device_with_session: Tropic01) -> None:
        """Test initializing counter with zero value."""
        index = 0

        # Initialize with zero
        device_with_session.counters.init(index=index, value=0)

        # Verify
        value = device_with_session.counters.get(index)
        assert value == 0

        # Update should fail immediately
        with pytest.raises(CounterInvalidError):
            device_with_session.counters.update(index)

    def test_mcounter_indexed_access(self, device_with_session: Tropic01) -> None:
        """Test indexed read access: counters[index]."""
        index = 0
        test_value = 42

        device_with_session.counters.init(index=index, value=test_value)

        # Use indexed access
        value = device_with_session.counters[index]
        assert value == test_value

    def test_mcounter_decrement_method(self, device_with_session: Tropic01) -> None:
        """Test decrement() convenience method that returns new value."""
        index = 0
        initial_value = 10

        device_with_session.counters.init(index=index, value=initial_value)

        # Decrement and get value in one call
        new_value = device_with_session.counters.decrement(index)
        assert new_value == initial_value - 1

        # Decrement again
        new_value = device_with_session.counters.decrement(index)
        assert new_value == initial_value - 2

    def test_mcounter_enum_index(self, device_with_session: Tropic01) -> None:
        """Test using McounterIndex enum for index parameter."""
        test_value = 50

        device_with_session.counters.init(
            index=McounterIndex.COUNTER_5,
            value=test_value
        )

        value = device_with_session.counters.get(McounterIndex.COUNTER_5)
        assert value == test_value

    def test_mcounter_multiple_updates(self, device_with_session: Tropic01) -> None:
        """Test multiple consecutive updates."""
        index = 0
        initial_value = 100
        num_updates = 50

        device_with_session.counters.init(index=index, value=initial_value)

        for i in range(num_updates):
            device_with_session.counters.update(index)

        final_value = device_with_session.counters.get(index)
        assert final_value == initial_value - num_updates, (
            f"Expected {initial_value - num_updates}, got {final_value}"
        )

    def test_mcounter_independent(self, device_with_session: Tropic01) -> None:
        """Test that counters are independent (updating one doesn't affect others)."""
        # Initialize all counters with different values
        for index in range(MCOUNTER_MIN, MCOUNTER_MAX + 1):
            device_with_session.counters.init(index=index, value=1000 + index)

        # Update only counter 0
        device_with_session.counters.update(0)

        # Verify counter 0 decremented
        assert device_with_session.counters.get(0) == 999

        # Verify other counters unchanged
        for index in range(1, MCOUNTER_MAX + 1):
            value = device_with_session.counters.get(index)
            assert value == 1000 + index, (
                f"Counter {index} changed unexpectedly to {value}"
            )

