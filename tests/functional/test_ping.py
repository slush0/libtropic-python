"""
Test Ping L3 command.

Mirrors: libtropic-upstream/tests/functional/lt_test_rev_ping.c

The Ping command echoes data through the secure channel, useful for
verifying session integrity.
"""

import pytest

from libtropic import Tropic01

from ..conftest import (
    PING_LEN_MAX,
    generate_random_length,
    generate_test_data,
)


# Number of ping iterations (matches C test)
PING_MAX_LOOPS = 200


@pytest.mark.hardware
@pytest.mark.destructive
class TestPing:
    """Tests for the Ping L3 command."""

    def test_ping_random_data_random_length(self, device_with_session: Tropic01) -> None:
        """
        Test Ping command with random data of random length.

        Sends PING_MAX_LOOPS pings with random data of random length <= PING_LEN_MAX.
        Verifies that received data matches sent data.

        Maps to: lt_test_rev_ping()
        """
        for i in range(PING_MAX_LOOPS):
            # Generate random length (0 to PING_LEN_MAX)
            ping_len = generate_random_length(PING_LEN_MAX, min_len=0)

            # Generate random data
            ping_data_out = generate_test_data(ping_len)

            # Send ping and verify echo
            ping_data_in = device_with_session.ping(ping_data_out)

            # Verify received data matches sent data
            assert ping_data_in == ping_data_out, (
                f"Ping {i}: Data mismatch. "
                f"Sent {len(ping_data_out)} bytes, received {len(ping_data_in)} bytes"
            )

    def test_ping_empty_data(self, device_with_session: Tropic01) -> None:
        """Test Ping with empty data (0 bytes)."""
        ping_data_out = b""
        ping_data_in = device_with_session.ping(ping_data_out)
        assert ping_data_in == ping_data_out

    def test_ping_single_byte(self, device_with_session: Tropic01) -> None:
        """Test Ping with single byte."""
        ping_data_out = b"\x42"
        ping_data_in = device_with_session.ping(ping_data_out)
        assert ping_data_in == ping_data_out

    def test_ping_max_length(self, device_with_session: Tropic01) -> None:
        """Test Ping with maximum length data."""
        ping_data_out = generate_test_data(PING_LEN_MAX)
        ping_data_in = device_with_session.ping(ping_data_out)
        assert ping_data_in == ping_data_out

    def test_ping_known_pattern(self, device_with_session: Tropic01) -> None:
        """Test Ping with known pattern to verify no data corruption."""
        # Ascending bytes pattern
        ping_data_out = bytes(range(256))
        ping_data_in = device_with_session.ping(ping_data_out)
        assert ping_data_in == ping_data_out

        # All zeros
        ping_data_out = bytes(256)
        ping_data_in = device_with_session.ping(ping_data_out)
        assert ping_data_in == ping_data_out

        # All ones
        ping_data_out = bytes([0xFF] * 256)
        ping_data_in = device_with_session.ping(ping_data_out)
        assert ping_data_in == ping_data_out

