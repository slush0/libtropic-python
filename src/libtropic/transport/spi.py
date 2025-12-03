"""
Linux SPI transport for libtropic.

Provides native SPI communication using Linux spidev and GPIO interfaces.
Suitable for Raspberry Pi, BeagleBone, and other Linux SBCs.
"""

from dataclasses import dataclass
from typing import Any

from .base import Transport


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
    """

    def __init__(self, config: SpiConfig):
        """
        Initialize SPI transport with given configuration.

        Args:
            config: SPI configuration parameters
        """
        self.config = config
        self._spi: Any = None
        self._gpio_chip: Any = None
        self._cs_line: Any = None
        self._int_line: Any = None

    def open(self) -> None:
        """
        Initialize SPI and GPIO interfaces.

        Raises:
            ImportError: If required packages are not installed
            ConnectionError: If devices cannot be opened
        """
        raise NotImplementedError("SPI transport not yet implemented")

    def close(self) -> None:
        """Close SPI and GPIO interfaces."""
        raise NotImplementedError("SPI transport not yet implemented")

    def spi_transfer(self, data: bytes, timeout_ms: int = 70) -> bytes:
        """Perform SPI transfer."""
        raise NotImplementedError("SPI transport not yet implemented")

    def cs_low(self) -> None:
        """Assert chip select (drive low)."""
        raise NotImplementedError("SPI transport not yet implemented")

    def cs_high(self) -> None:
        """Deassert chip select (drive high)."""
        raise NotImplementedError("SPI transport not yet implemented")

    def delay_ms(self, ms: int) -> None:
        """Delay for specified milliseconds."""
        raise NotImplementedError("SPI transport not yet implemented")

    def random_bytes(self, count: int) -> bytes:
        """Generate random bytes using os.urandom."""
        raise NotImplementedError("SPI transport not yet implemented")

    def wait_for_interrupt(self, timeout_ms: int) -> bool:
        """Wait for interrupt pin to signal."""
        raise NotImplementedError("SPI transport not yet implemented")

    @property
    def supports_interrupt(self) -> bool:
        """Check if interrupt pin is configured."""
        return self.config.int_pin is not None
