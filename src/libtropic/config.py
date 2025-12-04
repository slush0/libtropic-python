"""
Configuration operations for libtropic.

Provides access to TROPIC01's R-Config and I-Config storage.
"""

from typing import TYPE_CHECKING

from .enums import ConfigAddress
from .types import DeviceConfig

if TYPE_CHECKING:
    from .device import Tropic01


class Configuration:
    """
    Device configuration access.

    TROPIC01 has two configuration areas:

    - **R-Config**: Rewritable configuration in R-Memory
      - Can be read, written, and erased
      - Used for runtime settings

    - **I-Config**: Immutable configuration in I-Memory
      - Can be read, and individual bits can be set to 0 (irreversibly)
      - Used for permanent security policies
      - Has narrower temperature range (-20°C to 85°C)

    Both configurations control User Access Privileges (UAP) that determine
    which operations are permitted.

    Example:
        with Tropic01("/dev/ttyACM0") as device:
            device.start_session(priv_key, pub_key, slot=0)

            # Read a config value
            value = device.config.read_r(ConfigAddress.UAP_PING)

            # Write a config value
            device.config.write_r(ConfigAddress.UAP_PING, 0xFFFFFFFF)

            # Read all R-Config
            config = device.config.read_all_r()
    """

    def __init__(self, device: 'Tropic01'):
        """
        Initialize configuration module.

        Args:
            device: Parent Tropic01 device instance
        """
        self._device = device

    # =========================================================================
    # R-Config (Rewritable)
    # =========================================================================

    def read_r(self, address: ConfigAddress) -> int:
        """
        Read R-Config object at specified address.

        Args:
            address: Configuration object address

        Returns:
            32-bit configuration value

        Raises:
            NoSessionError: If no secure session is active
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_r_config_read()
        """
        from ._protocol.constants import L3_CMD_R_CONFIG_READ

        addr = int(address)

        # Build command: address(2B LE)
        cmd_data = bytes([addr & 0xFF, (addr >> 8) & 0xFF])

        # Send command and get response
        # Response: padding(3B) + value(4B LE)
        response = self._device._send_l3_command(L3_CMD_R_CONFIG_READ, cmd_data)

        # Parse value (skip 3 bytes padding)
        value = (response[3] |
                 (response[4] << 8) |
                 (response[5] << 16) |
                 (response[6] << 24))

        return value

    def write_r(self, address: ConfigAddress, value: int) -> None:
        """
        Write R-Config object at specified address.

        Args:
            address: Configuration object address
            value: 32-bit configuration value to write

        Raises:
            NoSessionError: If no secure session is active
            UnauthorizedError: If operation not permitted by UAP config
            HardwareError: If write operation fails

        Maps to: lt_r_config_write()
        """
        from ._protocol.constants import L3_CMD_R_CONFIG_WRITE

        addr = int(address)

        # Build command: address(2B LE) + padding(1B) + value(4B LE)
        cmd_data = bytearray(7)
        cmd_data[0] = addr & 0xFF
        cmd_data[1] = (addr >> 8) & 0xFF
        cmd_data[2] = 0  # padding
        cmd_data[3] = value & 0xFF
        cmd_data[4] = (value >> 8) & 0xFF
        cmd_data[5] = (value >> 16) & 0xFF
        cmd_data[6] = (value >> 24) & 0xFF

        # Send command - response is empty (just result code)
        self._device._send_l3_command(L3_CMD_R_CONFIG_WRITE, bytes(cmd_data))

    def erase_r(self) -> None:
        """
        Erase all R-Config objects.

        Resets all R-Config values to their default state.

        Raises:
            NoSessionError: If no secure session is active
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_r_config_erase()
        """
        from ._protocol.constants import L3_CMD_R_CONFIG_ERASE

        # Send command - no data, response is empty (just result code)
        self._device._send_l3_command(L3_CMD_R_CONFIG_ERASE, b"")

    def read_all_r(self) -> DeviceConfig:
        """
        Read all R-Config objects.

        Convenience method that reads all configuration objects at once.

        Returns:
            DeviceConfig with all R-Config values

        Raises:
            NoSessionError: If no secure session is active
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_read_whole_R_config()
        """
        result = {}
        for addr in ConfigAddress:
            result[addr] = self.read_r(addr)
        return DeviceConfig.from_address_dict(result)

    def write_all_r(self, config: dict[ConfigAddress, int]) -> None:
        """
        Write all R-Config objects.

        Convenience method that writes all configuration objects at once.

        Args:
            config: Dict mapping ConfigAddress to values to write

        Raises:
            NoSessionError: If no secure session is active
            UnauthorizedError: If operation not permitted by UAP config
            HardwareError: If write operation fails

        Maps to: lt_write_whole_R_config()
        """
        for addr, value in config.items():
            self.write_r(addr, value)

    # =========================================================================
    # I-Config (Immutable)
    # =========================================================================

    def read_i(self, address: ConfigAddress) -> int:
        """
        Read I-Config object at specified address.

        Args:
            address: Configuration object address

        Returns:
            32-bit configuration value

        Raises:
            NoSessionError: If no secure session is active
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_i_config_read()
        """
        from ._protocol.constants import L3_CMD_I_CONFIG_READ

        addr = int(address)

        # Build command: address(2B LE)
        cmd_data = bytes([addr & 0xFF, (addr >> 8) & 0xFF])

        # Send command and get response
        # Response: padding(3B) + value(4B LE)
        response = self._device._send_l3_command(L3_CMD_I_CONFIG_READ, cmd_data)

        # Parse value (skip 3 bytes padding)
        value = (response[3] |
                 (response[4] << 8) |
                 (response[5] << 16) |
                 (response[6] << 24))

        return value

    def write_i_bit(self, address: ConfigAddress, bit_index: int) -> None:
        """
        Set I-Config bit to 0 (irreversible).

        WARNING: This operation is PERMANENT. Once a bit is set to 0,
        it cannot be changed back to 1.

        I-Config resides in I-Memory which has narrower operating temperature
        range (-20°C to 85°C).

        Args:
            address: Configuration object address
            bit_index: Bit position to set to 0 (0-31)

        Raises:
            NoSessionError: If no secure session is active
            ParamError: If bit_index is out of range
            UnauthorizedError: If operation not permitted by UAP config
            HardwareError: If write operation fails

        Maps to: lt_i_config_write()
        """
        from ._protocol.constants import L3_CMD_I_CONFIG_WRITE
        from .enums import ReturnCode
        from .exceptions import ParamError

        if bit_index < 0 or bit_index > 31:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Bit index must be 0-31, got {bit_index}"
            )

        addr = int(address)

        # Build command: address(2B LE) + padding(1B) + bit_index(4B LE)
        cmd_data = bytearray(7)
        cmd_data[0] = addr & 0xFF
        cmd_data[1] = (addr >> 8) & 0xFF
        cmd_data[2] = 0  # padding
        cmd_data[3] = bit_index & 0xFF
        cmd_data[4] = (bit_index >> 8) & 0xFF
        cmd_data[5] = (bit_index >> 16) & 0xFF
        cmd_data[6] = (bit_index >> 24) & 0xFF

        # Send command - response is empty (just result code)
        self._device._send_l3_command(L3_CMD_I_CONFIG_WRITE, bytes(cmd_data))

    def read_all_i(self) -> DeviceConfig:
        """
        Read all I-Config objects.

        Convenience method that reads all I-Config values at once.

        Returns:
            DeviceConfig with all I-Config values

        Raises:
            NoSessionError: If no secure session is active
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_read_whole_I_config()
        """
        result = {}
        for addr in ConfigAddress:
            result[addr] = self.read_i(addr)
        return DeviceConfig.from_address_dict(result)

    def write_all_i(self, config: dict[ConfigAddress, int]) -> None:
        """
        Write all I-Config objects (set 0-bits only).

        For each configuration object, only bits that are 0 in the provided
        config will be written. This operation is IRREVERSIBLE.

        WARNING: This permanently modifies I-Config. Only 0-bits are written.
        I-Config resides in I-Memory which has narrower operating temperature
        range (-20°C to 85°C).

        Args:
            config: Dict mapping ConfigAddress to desired final values
                    (0 bits will be written, 1 bits ignored)

        Raises:
            NoSessionError: If no secure session is active
            UnauthorizedError: If operation not permitted by UAP config
            HardwareError: If write operation fails

        Maps to: lt_write_whole_I_config()
        """
        # Iterate through all config addresses in the provided dict
        for addr, value in config.items():
            # For each bit position (0-31), if the bit is 0 in the config value,
            # write it to I-Config (irreversible transition from 1 to 0)
            for bit_index in range(32):
                if not value & (1 << bit_index):
                    # Bit is 0 - write it to I-Config
                    self.write_i_bit(addr, bit_index)
