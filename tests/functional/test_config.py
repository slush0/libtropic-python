"""
Test R-Config and I-Config Read, Write, and Erase L3 commands.

Mirrors:
    - libtropic-upstream/tests/functional/lt_test_rev_read_r_config.c
    - libtropic-upstream/tests/functional/lt_test_rev_write_r_config.c
    - libtropic-upstream/tests/functional/lt_test_rev_erase_r_config.c
    - libtropic-upstream/tests/functional/lt_test_rev_read_i_config.c
    - libtropic-upstream/tests/functional/lt_test_ire_write_i_config.c

Tests device configuration operations.

WARNING: I-Config tests are IRREVERSIBLE and permanently modify the device!
"""

import pytest

from libtropic import ConfigAddress, Tropic01
from libtropic.types import DeviceConfig


@pytest.mark.hardware
@pytest.mark.destructive
class TestRConfigRead:
    """
    Tests for R_Config_Read command.

    Maps to: lt_test_rev_read_r_config()
    """

    def test_read_r_config_all_addresses(self, device_with_session: Tropic01) -> None:
        """Test reading all R-Config addresses."""
        addresses = [
            ConfigAddress.START_UP,
            ConfigAddress.SENSORS,
            ConfigAddress.DEBUG,
            ConfigAddress.GPO,
            ConfigAddress.SLEEP_MODE,
            ConfigAddress.UAP_PAIRING_KEY_WRITE,
            ConfigAddress.UAP_PAIRING_KEY_READ,
            ConfigAddress.UAP_PAIRING_KEY_INVALIDATE,
            ConfigAddress.UAP_R_CONFIG_WRITE_ERASE,
            ConfigAddress.UAP_R_CONFIG_READ,
            ConfigAddress.UAP_I_CONFIG_WRITE,
            ConfigAddress.UAP_I_CONFIG_READ,
            ConfigAddress.UAP_PING,
            ConfigAddress.UAP_R_MEM_DATA_WRITE,
            ConfigAddress.UAP_R_MEM_DATA_READ,
            ConfigAddress.UAP_R_MEM_DATA_ERASE,
            ConfigAddress.UAP_RANDOM_VALUE_GET,
            ConfigAddress.UAP_ECC_KEY_GENERATE,
            ConfigAddress.UAP_ECC_KEY_STORE,
            ConfigAddress.UAP_ECC_KEY_READ,
            ConfigAddress.UAP_ECC_KEY_ERASE,
            ConfigAddress.UAP_ECDSA_SIGN,
            ConfigAddress.UAP_EDDSA_SIGN,
            ConfigAddress.UAP_MCOUNTER_INIT,
            ConfigAddress.UAP_MCOUNTER_GET,
            ConfigAddress.UAP_MCOUNTER_UPDATE,
            ConfigAddress.UAP_MAC_AND_DESTROY,
        ]

        for address in addresses:
            value = device_with_session.config.read_r(address)
            # Value should be a 32-bit integer
            assert 0 <= value <= 0xFFFFFFFF, f"Address {address}: Invalid value {value}"

    def test_read_all_r_config(self, device_with_session: Tropic01) -> None:
        """Test reading all R-Config as DeviceConfig object."""
        config: DeviceConfig = device_with_session.config.read_all_r()

        # Verify all fields are valid 32-bit integers
        assert 0 <= config.start_up <= 0xFFFFFFFF
        assert 0 <= config.sensors <= 0xFFFFFFFF
        assert 0 <= config.debug <= 0xFFFFFFFF
        assert 0 <= config.uap_ping <= 0xFFFFFFFF


@pytest.mark.hardware
@pytest.mark.destructive
class TestRConfigWrite:
    """
    Tests for R_Config_Write command.

    Maps to: lt_test_rev_write_r_config()
    """

    def test_write_read_r_config(self, device_with_session: Tropic01) -> None:
        """Test writing and reading R-Config values."""
        # Save original values
        original_values: dict[ConfigAddress, int] = {}
        addresses = [
            ConfigAddress.UAP_PING,
            ConfigAddress.UAP_RANDOM_VALUE_GET,
        ]

        for address in addresses:
            original_values[address] = device_with_session.config.read_r(address)

        try:
            # Write test values
            test_values = {
                ConfigAddress.UAP_PING: 0xAAAAAAAA,
                ConfigAddress.UAP_RANDOM_VALUE_GET: 0x55555555,
            }

            for address, value in test_values.items():
                device_with_session.config.write_r(address, value)

            # Verify written values
            for address, expected in test_values.items():
                actual = device_with_session.config.read_r(address)
                assert actual == expected, (
                    f"Address {address}: Expected 0x{expected:08X}, got 0x{actual:08X}"
                )

        finally:
            # Restore original values
            for address, value in original_values.items():
                device_with_session.config.write_r(address, value)


@pytest.mark.hardware
@pytest.mark.destructive
class TestRConfigErase:
    """
    Tests for R_Config_Erase command.

    Maps to: lt_test_rev_erase_r_config()
    """

    def test_erase_r_config(self, device_with_session: Tropic01) -> None:
        """
        Test erasing all R-Config.

        After erase, all R-Config values should return to defaults (0xFFFFFFFF).
        """
        # First, write some non-default values
        device_with_session.config.write_r(ConfigAddress.UAP_PING, 0x12345678)

        # Erase all R-Config
        device_with_session.config.erase_r()

        # Verify values are reset to defaults
        value = device_with_session.config.read_r(ConfigAddress.UAP_PING)
        assert value == 0xFFFFFFFF, f"Expected 0xFFFFFFFF after erase, got 0x{value:08X}"


@pytest.mark.hardware
@pytest.mark.destructive
class TestIConfigRead:
    """
    Tests for I_Config_Read command.

    Maps to: lt_test_rev_read_i_config()
    """

    def test_read_i_config_all_addresses(self, device_with_session: Tropic01) -> None:
        """Test reading all I-Config addresses."""
        addresses = [
            ConfigAddress.START_UP,
            ConfigAddress.SENSORS,
            ConfigAddress.DEBUG,
            ConfigAddress.GPO,
            ConfigAddress.SLEEP_MODE,
            ConfigAddress.UAP_PAIRING_KEY_WRITE,
            ConfigAddress.UAP_PAIRING_KEY_READ,
            ConfigAddress.UAP_PAIRING_KEY_INVALIDATE,
            ConfigAddress.UAP_R_CONFIG_WRITE_ERASE,
            ConfigAddress.UAP_R_CONFIG_READ,
            ConfigAddress.UAP_I_CONFIG_WRITE,
            ConfigAddress.UAP_I_CONFIG_READ,
            ConfigAddress.UAP_PING,
            ConfigAddress.UAP_R_MEM_DATA_WRITE,
            ConfigAddress.UAP_R_MEM_DATA_READ,
            ConfigAddress.UAP_R_MEM_DATA_ERASE,
            ConfigAddress.UAP_RANDOM_VALUE_GET,
            ConfigAddress.UAP_ECC_KEY_GENERATE,
            ConfigAddress.UAP_ECC_KEY_STORE,
            ConfigAddress.UAP_ECC_KEY_READ,
            ConfigAddress.UAP_ECC_KEY_ERASE,
            ConfigAddress.UAP_ECDSA_SIGN,
            ConfigAddress.UAP_EDDSA_SIGN,
            ConfigAddress.UAP_MCOUNTER_INIT,
            ConfigAddress.UAP_MCOUNTER_GET,
            ConfigAddress.UAP_MCOUNTER_UPDATE,
            ConfigAddress.UAP_MAC_AND_DESTROY,
        ]

        for address in addresses:
            value = device_with_session.config.read_i(address)
            # Value should be a 32-bit integer
            assert 0 <= value <= 0xFFFFFFFF, f"Address {address}: Invalid value {value}"

    def test_read_all_i_config(self, device_with_session: Tropic01) -> None:
        """Test reading all I-Config as DeviceConfig object."""
        config: DeviceConfig = device_with_session.config.read_all_i()

        # Verify all fields are valid 32-bit integers
        assert 0 <= config.start_up <= 0xFFFFFFFF
        assert 0 <= config.sensors <= 0xFFFFFFFF
        assert 0 <= config.debug <= 0xFFFFFFFF
        assert 0 <= config.uap_ping <= 0xFFFFFFFF


@pytest.mark.hardware
@pytest.mark.irreversible
class TestIConfigWrite:
    """
    Tests for I_Config_Write command.

    Maps to: lt_test_ire_write_i_config()

    WARNING: These tests PERMANENTLY modify the device! They can only set
    bits to 0, never back to 1. Only run on test/development devices!
    """

    def test_write_i_config_bit_warning(self, device_with_session: Tropic01) -> None:
        """
        This test demonstrates I-Config write but DOES NOT execute it
        to prevent accidental permanent modification.

        To actually test I-Config write, use a dedicated test device
        and uncomment the write operation.
        """
        # Read current value
        current = device_with_session.config.read_i(ConfigAddress.UAP_PING)

        # Find a bit that is currently 1 (can be set to 0)
        # WARNING: This is IRREVERSIBLE!

        # DO NOT UNCOMMENT unless you understand the consequences:
        # device_with_session.config.write_i_bit(ConfigAddress.UAP_PING, bit_index=0)

        # This test intentionally does nothing to prevent accidents
        assert current is not None  # Just verify we can read

    def test_write_all_i_config_warning(self, device_with_session: Tropic01) -> None:
        """
        This test demonstrates I-Config write_all but DOES NOT execute it.

        WARNING: write_all_i() permanently sets 0-bits in the config!
        """
        # Read current I-Config
        current_config: DeviceConfig = device_with_session.config.read_all_i()

        # DO NOT UNCOMMENT unless you understand the consequences:
        # The following would permanently set any 0-bits in new_config:
        # new_config = DeviceConfig(uap_ping=0xFFFFFFFE)  # Clear bit 0
        # device_with_session.config.write_all_i(new_config)

        # This test intentionally does nothing to prevent accidents
        assert current_config is not None  # Just verify we can read

