"""
USB dongle transport for libtropic.

Provides communication via the TS1302 USB-to-SPI bridge dongle.
The dongle uses a serial protocol to translate UART commands to SPI.
"""

from dataclasses import dataclass
from typing import Optional, Any

from .base import Transport


@dataclass
class UsbDongleConfig:
    """
    Configuration for USB dongle (TS1302) transport.

    Attributes:
        device_path: Path to serial device (e.g., "/dev/ttyACM0" on Linux,
                     "COM3" on Windows, "/dev/cu.usbmodem*" on macOS)
        baud_rate: UART baud rate (default: 115200)
    """
    device_path: str = "/dev/ttyACM0"
    baud_rate: int = 115200


class UsbDongleTransport(Transport):
    """
    Transport for TROPIC01 via USB serial dongle (TS1302 evaluation kit).

    The TS1302 dongle translates UART commands to SPI, allowing communication
    with TROPIC01 from any system with USB support.

    Protocol documentation:
        https://github.com/tropicsquare/ts13-usb-dev-kit-fw

    Requirements:
        - pyserial package: pip install pyserial

    Example:
        config = UsbDongleConfig(
            device_path="/dev/ttyACM0",
            baud_rate=115200
        )

        with UsbDongleTransport(config) as transport:
            device = Tropic01(transport)
            ...

    Platform-specific device paths:
        - Linux: /dev/ttyACM0 or /dev/ttyUSB0
        - macOS: /dev/cu.usbmodem* or /dev/tty.usbmodem*
        - Windows: COM3, COM4, etc.
    """

    def __init__(self, config: UsbDongleConfig):
        """
        Initialize USB dongle transport with given configuration.

        Args:
            config: USB dongle configuration parameters
        """
        self.config = config
        self._serial: Any = None

    def open(self) -> None:
        """
        Open serial connection to USB dongle.

        Raises:
            ImportError: If pyserial is not installed
            ConnectionError: If device cannot be opened
        """
        raise NotImplementedError("USB dongle transport not yet implemented")

    def close(self) -> None:
        """Close serial connection."""
        raise NotImplementedError("USB dongle transport not yet implemented")

    def spi_transfer(self, data: bytes, timeout_ms: int = 70) -> bytes:
        """
        Perform SPI transfer via dongle protocol.

        The dongle handles chip select internally as part of the transfer.
        """
        raise NotImplementedError("USB dongle transport not yet implemented")

    def cs_low(self) -> None:
        """
        Assert chip select.

        Note: For USB dongle, CS is handled as part of the transfer protocol.
        This is a no-op but required by the interface.
        """
        pass  # Handled by dongle protocol

    def cs_high(self) -> None:
        """
        Deassert chip select.

        Note: For USB dongle, CS is handled as part of the transfer protocol.
        This is a no-op but required by the interface.
        """
        pass  # Handled by dongle protocol

    def delay_ms(self, ms: int) -> None:
        """Delay for specified milliseconds."""
        raise NotImplementedError("USB dongle transport not yet implemented")

    def random_bytes(self, count: int) -> bytes:
        """Generate random bytes using os.urandom."""
        raise NotImplementedError("USB dongle transport not yet implemented")

    @property
    def supports_interrupt(self) -> bool:
        """USB dongle does not support interrupt pin monitoring."""
        return False
