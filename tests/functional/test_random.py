"""
Test Random Value Get L3 command.

Mirrors: libtropic-upstream/tests/functional/lt_test_rev_random_value_get.c

Tests hardware random number generation from TROPIC01's RNG.
"""

import pytest

from libtropic import ParamError, Tropic01

# Maximum bytes per request
RANDOM_VALUE_MAX_LEN = 255


@pytest.mark.hardware
@pytest.mark.destructive
class TestRandomValueGet:
    """Tests for the Random_Value_Get L3 command."""

    def test_random_value_get_various_lengths(self, device_with_session: Tropic01) -> None:
        """
        Test getting random values of various lengths.

        Maps to: lt_test_rev_random_value_get()
        """
        # Test various lengths from 1 to max
        test_lengths = [1, 16, 32, 64, 128, 255]

        for length in test_lengths:
            random_data = device_with_session.random.get_bytes(length)

            # Verify correct length returned
            assert len(random_data) == length, (
                f"Expected {length} bytes, got {len(random_data)}"
            )

    def test_random_value_get_max_length(self, device_with_session: Tropic01) -> None:
        """Test getting maximum length random value."""
        random_data = device_with_session.random.get_bytes(RANDOM_VALUE_MAX_LEN)
        assert len(random_data) == RANDOM_VALUE_MAX_LEN

    def test_random_value_get_single_byte(self, device_with_session: Tropic01) -> None:
        """Test getting single random byte."""
        random_data = device_with_session.random.get_bytes(1)
        assert len(random_data) == 1

    def test_random_value_uniqueness(self, device_with_session: Tropic01) -> None:
        """
        Test that random values are actually random (not repeating).

        Note: This is a weak randomness test - just checks for obvious
        failures like returning constant values.
        """
        values = set()
        num_samples = 100

        for _ in range(num_samples):
            random_data = device_with_session.random.get_bytes(32)
            values.add(random_data)

        # All 100 samples should be unique (statistically virtually certain)
        assert len(values) == num_samples, (
            f"Expected {num_samples} unique values, got {len(values)}"
        )

    def test_random_value_callable_syntax(self, device_with_session: Tropic01) -> None:
        """Test callable syntax: device.random(32)."""
        random_data = device_with_session.random(32)
        assert len(random_data) == 32

    def test_random_value_invalid_length_zero(self, device_with_session: Tropic01) -> None:
        """Test that requesting 0 bytes raises ParamError."""
        with pytest.raises(ParamError):
            device_with_session.random.get_bytes(0)

    def test_random_value_invalid_length_too_large(self, device_with_session: Tropic01) -> None:
        """Test that requesting > 255 bytes raises ParamError."""
        with pytest.raises(ParamError):
            device_with_session.random.get_bytes(256)

