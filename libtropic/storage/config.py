"""
Configuration operations for libtropic.

Provides access to TROPIC01's R-Config and I-Config storage.
"""

from typing import TYPE_CHECKING, Dict

from ..enums import ConfigAddress
from ..types import DeviceConfig

if TYPE_CHECKING:
    from ..device import Tropic01


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
        raise NotImplementedError()

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
        raise NotImplementedError()

    def erase_r(self) -> None:
        """
        Erase all R-Config objects.

        Resets all R-Config values to their default state.

        Raises:
            NoSessionError: If no secure session is active
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_r_config_erase()
        """
        raise NotImplementedError()

    def read_all_r(self) -> DeviceConfig:
        """
        Read all R-Config objects.

        Convenience method that reads all configuration objects at once.

        Returns:
            DeviceConfig containing all R-Config values

        Raises:
            NoSessionError: If no secure session is active
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_read_whole_R_config()
        """
        raise NotImplementedError()

    def write_all_r(self, config: DeviceConfig) -> None:
        """
        Write all R-Config objects.

        Convenience method that writes all configuration objects at once.

        Args:
            config: DeviceConfig containing values to write

        Raises:
            NoSessionError: If no secure session is active
            UnauthorizedError: If operation not permitted by UAP config
            HardwareError: If write operation fails

        Maps to: lt_write_whole_R_config()
        """
        raise NotImplementedError()

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
        raise NotImplementedError()

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
        raise NotImplementedError()

    def read_all_i(self) -> DeviceConfig:
        """
        Read all I-Config objects.

        Convenience method that reads all I-Config values at once.

        Returns:
            DeviceConfig containing all I-Config values

        Raises:
            NoSessionError: If no secure session is active
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_read_whole_I_config()
        """
        raise NotImplementedError()

    def write_all_i(self, config: DeviceConfig) -> None:
        """
        Write all I-Config objects (set 0-bits only).

        For each configuration object, only bits that are 0 in the provided
        config will be written. This operation is IRREVERSIBLE.

        WARNING: This permanently modifies I-Config. Only 0-bits are written.

        Args:
            config: DeviceConfig with desired final values
                    (0 bits will be written, 1 bits ignored)

        Raises:
            NoSessionError: If no secure session is active
            UnauthorizedError: If operation not permitted by UAP config
            HardwareError: If write operation fails

        Maps to: lt_write_whole_I_config()
        """
        raise NotImplementedError()
