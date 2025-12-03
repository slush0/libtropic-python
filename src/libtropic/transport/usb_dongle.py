"""
USB dongle transport for libtropic.

Provides communication via the TS1302 USB-to-SPI bridge dongle.
The dongle uses a serial protocol to translate UART commands to SPI.

Protocol details:
    - SPI data is hex-encoded for transmission (0xAB → "AB")
    - Transfers end with 'x\\n' to keep CS low during multi-byte transfers
    - CS is released by sending "CS=0\\n" (response: "OK\\r\\n")
    - More info: https://github.com/tropicsquare/ts13-usb-dev-kit-fw
"""

import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .base import Transport

if TYPE_CHECKING:
    from serial import Serial


# Delay between write and read operations on USB dongle (ms)
_USB_DONGLE_READ_WRITE_DELAY_MS = 5


@dataclass
class UsbDongleConfig:
    """
    Configuration for USB dongle (TS1302) transport.

    Attributes:
        device_path: Path to serial device (e.g., "/dev/ttyACM0" on Linux,
                     "COM3" on Windows, "/dev/cu.usbmodem*" on macOS)
        baud_rate: UART baud rate (default: 115200)
        read_timeout: Serial read timeout in seconds (default: 0.1)
    """
    device_path: str = "/dev/ttyACM0"
    baud_rate: int = 115200
    read_timeout: float = 0.1


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
        self._serial: "Serial | None" = None

    def open(self) -> None:
        """
        Open serial connection to USB dongle.

        Raises:
            ImportError: If pyserial is not installed
            ConnectionError: If device cannot be opened
        """
        try:
            import serial
        except ImportError as e:
            raise ImportError(
                "pyserial is required for USB dongle transport. "
                "Install it with: pip install pyserial"
            ) from e

        try:
            self._serial = serial.Serial(
                port=self.config.device_path,
                baudrate=self.config.baud_rate,
                timeout=self.config.read_timeout,
                # Raw mode settings (disable special character handling)
                xonxoff=False,
                rtscts=False,
                dsrdtr=False,
            )
            # Flush any stale data in buffers
            self._serial.reset_input_buffer()
            self._serial.reset_output_buffer()
        except Exception as e:
            raise ConnectionError(
                f"Failed to open serial port '{self.config.device_path}': {e}"
            ) from e

    def close(self) -> None:
        """Close serial connection."""
        if self._serial is not None:
            try:
                self._serial.close()
            except Exception:
                pass  # Ignore errors during close
            self._serial = None

    def spi_transfer(self, data: bytes, timeout_ms: int = 70) -> bytes:
        """
        Perform SPI transfer via dongle protocol.

        The dongle protocol encodes each byte as two hex characters,
        followed by 'x\\n' to keep CS low during the transfer.

        Args:
            data: Data bytes to transmit
            timeout_ms: Transfer timeout in milliseconds (unused, uses config timeout)

        Returns:
            Received data bytes (same length as input)

        Raises:
            RuntimeError: If transport is not open
            IOError: If communication fails
        """
        if self._serial is None:
            raise RuntimeError("Transport not open. Call open() first.")

        if not data:
            return b""

        # Encode data bytes as hex characters + 'x\n' suffix
        # Example: bytes([0x01, 0x02]) → b"0102x\n"
        hex_data = data.hex().upper().encode("ascii") + b"x\n"

        # Write to dongle
        written = self._serial.write(hex_data)
        if written != len(hex_data):
            raise IOError(f"Failed to write all data: {written}/{len(hex_data)}")

        # Small delay before reading (per C implementation)
        time.sleep(_USB_DONGLE_READ_WRITE_DELAY_MS / 1000.0)

        # Read response: same format as sent (hex chars + '\r\n')
        # Expected: len(data)*2 hex chars + 2 bytes for '\r\n'
        expected_len = len(data) * 2 + 2
        response = self._read_exact(expected_len)

        if len(response) != expected_len:
            raise IOError(
                f"Incomplete response: got {len(response)}, expected {expected_len}"
            )

        # Parse hex response (strip trailing \r\n)
        hex_response = response[:-2]  # Remove '\r\n'
        try:
            return bytes.fromhex(hex_response.decode("ascii"))
        except ValueError as e:
            raise IOError(f"Invalid hex response: {hex_response!r}") from e

    def cs_low(self) -> None:
        """
        Assert chip select.

        Note: For USB dongle, CS goes low automatically when SPI transfer starts.
        This is a no-op.
        """
        pass  # CS LOW is handled automatically during SPI transfer

    def cs_high(self) -> None:
        """
        Deassert chip select (release CS).

        Sends "CS=0\\n" to the dongle to release CS. Confusingly named in
        the dongle protocol - "CS=0" means CSN goes HIGH (deasserted).
        """
        if self._serial is None:
            raise RuntimeError("Transport not open. Call open() first.")

        # Send CS release command
        self._serial.write(b"CS=0\n")

        # Read confirmation response: "OK\r\n"
        response = self._read_exact(4)
        if response != b"OK\r\n":
            raise IOError(f"Unexpected CS release response: {response!r}")

    def delay_ms(self, ms: int) -> None:
        """
        Delay for specified milliseconds.

        Args:
            ms: Delay duration in milliseconds
        """
        time.sleep(ms / 1000.0)

    def random_bytes(self, count: int) -> bytes:
        """
        Generate cryptographically secure random bytes using os.urandom.

        Args:
            count: Number of random bytes to generate

        Returns:
            Random bytes
        """
        return os.urandom(count)

    @property
    def supports_interrupt(self) -> bool:
        """USB dongle does not support interrupt pin monitoring."""
        return False

    def _read_exact(self, count: int) -> bytes:
        """
        Read exactly `count` bytes from serial, handling partial reads.

        Args:
            count: Number of bytes to read

        Returns:
            Read bytes (may be shorter than count on timeout)
        """
        if self._serial is None:
            raise RuntimeError("Transport not open")

        result = bytearray()
        while len(result) < count:
            chunk = self._serial.read(count - len(result))
            if not chunk:
                # Timeout - no more data
                break
            result.extend(chunk)
        return bytes(result)
