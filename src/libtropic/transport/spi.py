"""
Linux SPI transport for libtropic.

Provides native SPI communication using Linux spidev and GPIO interfaces.
Suitable for Raspberry Pi, BeagleBone, and other Linux SBCs.

This implementation mirrors the C library's hal/linux/spi port, using:
- spidev for SPI communication (SPI_MODE_0)
- gpiod for GPIO control (chip select and optional interrupt pin)
"""

import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .base import Transport

if TYPE_CHECKING:
    pass


@dataclass
class SpiConfig:
    """
    Configuration for Linux SPI transport.

    Attributes:
        spi_device: Path to SPI device (e.g., "/dev/spidev0.0")
        spi_speed_hz: SPI clock speed in Hz (default: 1 MHz)
        gpio_chip: Path to GPIO chip device (e.g., "/dev/gpiochip0")
        cs_pin: GPIO pin number for chip select
        int_pin: Optional GPIO pin number for interrupt (None to disable)
    """
    spi_device: str = "/dev/spidev0.0"
    spi_speed_hz: int = 1_000_000
    gpio_chip: str = "/dev/gpiochip0"
    cs_pin: int = 8
    int_pin: int | None = None


class LinuxSpiTransport(Transport):
    """
    Native Linux SPI transport using spidev and GPIO.

    This transport communicates directly with TROPIC01 over SPI, suitable
    for single-board computers like Raspberry Pi or BeagleBone.

    Requirements:
        - spidev Python package: pip install spidev
        - gpiod Python package: pip install gpiod
        - Appropriate permissions for /dev/spidev* and /dev/gpiochip*

    Example:
        config = SpiConfig(
            spi_device="/dev/spidev0.0",
            spi_speed_hz=1_000_000,
            gpio_chip="/dev/gpiochip0",
            cs_pin=8,
            int_pin=25  # optional
        )

        with LinuxSpiTransport(config) as transport:
            device = Tropic01(transport)
            ...

    Wiring (typical Raspberry Pi):
        - MOSI -> GPIO 10 (SPI0 MOSI)
        - MISO -> GPIO 9 (SPI0 MISO)
        - SCLK -> GPIO 11 (SPI0 SCLK)
        - CS   -> GPIO 8 (directly controlled)
        - INT  -> GPIO 25 (optional)
        - GND  -> GND
        - VCC  -> 3.3V

    Note:
        The chip select (CS) pin is controlled separately using GPIO, as the
        TROPIC01 protocol requires manual handling of the chip select line.
        Do not use the hardware CS from spidev.
    """

    def __init__(self, config: SpiConfig):
        """
        Initialize SPI transport with given configuration.

        Args:
            config: SPI configuration parameters
        """
        self.config = config
        self._spi: Any = None
        self._cs_line: Any = None
        self._int_line: Any = None

    def open(self) -> None:
        """
        Initialize SPI and GPIO interfaces.

        Raises:
            ImportError: If required packages are not installed
            ConnectionError: If devices cannot be opened
        """
        # Import dependencies
        try:
            import spidev  # type: ignore[import-not-found]
        except ImportError as e:
            raise ImportError(
                "spidev is required for SPI transport. "
                "Install it with: pip install spidev"
            ) from e

        try:
            import gpiod  # type: ignore[import-not-found]
        except ImportError as e:
            raise ImportError(
                "gpiod is required for SPI transport. "
                "Install it with: pip install gpiod"
            ) from e

        # Initialize SPI
        try:
            self._spi = spidev.SpiDev()
            # Extract bus and device numbers from device path
            # e.g., "/dev/spidev0.0" → bus=0, device=0
            bus, device = self._parse_spi_device(self.config.spi_device)
            self._spi.open(bus, device)

            # Configure SPI: MODE_0 (CPOL=0, CPHA=0)
            self._spi.mode = 0
            self._spi.max_speed_hz = self.config.spi_speed_hz

            # Disable hardware CS - we control it manually via GPIO
            self._spi.no_cs = True

        except Exception as e:
            self._cleanup()
            raise ConnectionError(
                f"Failed to open SPI device '{self.config.spi_device}': {e}"
            ) from e

        # Initialize GPIO for chip select
        try:
            self._setup_gpio_cs(gpiod)
        except Exception as e:
            self._cleanup()
            raise ConnectionError(
                f"Failed to setup GPIO chip select on '{self.config.gpio_chip}' "
                f"pin {self.config.cs_pin}: {e}"
            ) from e

        # Initialize GPIO for interrupt pin (optional)
        if self.config.int_pin is not None:
            try:
                self._setup_gpio_int(gpiod)
            except Exception as e:
                self._cleanup()
                raise ConnectionError(
                    f"Failed to setup GPIO interrupt on '{self.config.gpio_chip}' "
                    f"pin {self.config.int_pin}: {e}"
                ) from e

    def _parse_spi_device(self, device_path: str) -> tuple[int, int]:
        """
        Parse SPI device path to extract bus and device numbers.

        Args:
            device_path: Path like "/dev/spidev0.0"

        Returns:
            Tuple of (bus, device) numbers

        Raises:
            ValueError: If device path format is invalid
        """
        # Extract "0.0" from "/dev/spidev0.0"
        import re
        match = re.search(r"spidev(\d+)\.(\d+)$", device_path)
        if not match:
            raise ValueError(
                f"Invalid SPI device path: '{device_path}'. "
                f"Expected format: /dev/spidevX.Y"
            )
        return int(match.group(1)), int(match.group(2))

    def _setup_gpio_cs(self, gpiod: Any) -> None:
        """
        Setup GPIO line for chip select (output, initially high).

        Args:
            gpiod: The gpiod module
        """
        # Request the CS line as output with initial value HIGH (deasserted)
        self._cs_line = gpiod.request_lines(
            self.config.gpio_chip,
            consumer="libtropic-cs",
            config={
                self.config.cs_pin: gpiod.LineSettings(
                    direction=gpiod.line.Direction.OUTPUT,
                    output_value=gpiod.line.Value.ACTIVE,  # HIGH = deasserted
                )
            }
        )

    def _setup_gpio_int(self, gpiod: Any) -> None:
        """
        Setup GPIO line for interrupt pin (input, rising edge detection).

        Args:
            gpiod: The gpiod module
        """
        self._int_line = gpiod.request_lines(
            self.config.gpio_chip,
            consumer="libtropic-int",
            config={
                self.config.int_pin: gpiod.LineSettings(
                    direction=gpiod.line.Direction.INPUT,
                    edge_detection=gpiod.line.Edge.RISING,
                )
            }
        )

    def _cleanup(self) -> None:
        """Release all resources, ignoring errors."""
        if self._int_line is not None:
            try:
                self._int_line.release()
            except Exception:
                pass
            self._int_line = None

        if self._cs_line is not None:
            try:
                self._cs_line.release()
            except Exception:
                pass
            self._cs_line = None

        if self._spi is not None:
            try:
                self._spi.close()
            except Exception:
                pass
            self._spi = None

    def close(self) -> None:
        """Close SPI and GPIO interfaces."""
        self._cleanup()

    def spi_transfer(self, data: bytes, timeout_ms: int = 70) -> bytes:
        """
        Perform full-duplex SPI transfer.

        Args:
            data: Data bytes to transmit
            timeout_ms: Transfer timeout in milliseconds (unused for spidev)

        Returns:
            Received data bytes (same length as input)

        Raises:
            RuntimeError: If transport is not open
            IOError: If SPI transfer fails
        """
        if self._spi is None:
            raise RuntimeError("Transport not open. Call open() first.")

        if not data:
            return b""

        # spidev.xfer2() performs full-duplex transfer and keeps CS asserted
        # between bytes (we control CS manually anyway)
        try:
            result = self._spi.xfer2(list(data))
            return bytes(result)
        except Exception as e:
            raise OSError(f"SPI transfer failed: {e}") from e

    def cs_low(self) -> None:
        """
        Assert chip select (drive low).

        Raises:
            RuntimeError: If transport is not open
            IOError: If GPIO operation fails
        """
        if self._cs_line is None:
            raise RuntimeError("Transport not open. Call open() first.")

        try:
            import gpiod  # type: ignore[import-not-found]
            self._cs_line.set_value(self.config.cs_pin, gpiod.line.Value.INACTIVE)
        except Exception as e:
            raise OSError(f"Failed to assert CS: {e}") from e

    def cs_high(self) -> None:
        """
        Deassert chip select (drive high).

        Raises:
            RuntimeError: If transport is not open
            IOError: If GPIO operation fails
        """
        if self._cs_line is None:
            raise RuntimeError("Transport not open. Call open() first.")

        try:
            import gpiod  # type: ignore[import-not-found]
            self._cs_line.set_value(self.config.cs_pin, gpiod.line.Value.ACTIVE)
        except Exception as e:
            raise OSError(f"Failed to deassert CS: {e}") from e

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

    def wait_for_interrupt(self, timeout_ms: int) -> bool:
        """
        Wait for interrupt pin to signal (rising edge).

        Args:
            timeout_ms: Maximum time to wait in milliseconds

        Returns:
            True if interrupt received, False if timeout

        Raises:
            RuntimeError: If transport is not open or interrupt not configured
            IOError: If GPIO operation fails
        """
        if self._int_line is None:
            if self.config.int_pin is None:
                raise RuntimeError(
                    "Interrupt pin not configured. Set int_pin in SpiConfig."
                )
            raise RuntimeError("Transport not open. Call open() first.")

        try:
            # Convert milliseconds to timedelta for gpiod
            from datetime import timedelta
            timeout = timedelta(milliseconds=timeout_ms)

            # Wait for edge event
            if self._int_line.wait_edge_events(timeout):
                # Consume the event to clear it
                self._int_line.read_edge_events()
                # We got a rising edge
                return True
            else:
                # Timeout
                return False

        except Exception as e:
            raise OSError(f"Failed to wait for interrupt: {e}") from e

    @property
    def supports_interrupt(self) -> bool:
        """Check if interrupt pin is configured."""
        return self.config.int_pin is not None
