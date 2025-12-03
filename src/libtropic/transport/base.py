"""
Abstract transport interface for libtropic.

Defines the contract that all transport implementations must follow.
"""

from abc import ABC, abstractmethod
from types import TracebackType


class Transport(ABC):
    """
    Abstract base class for TROPIC01 transport layers.

    The transport layer handles low-level communication with the TROPIC01 chip.
    Different implementations support different physical interfaces:
    - Native SPI (Linux spidev + GPIO)
    - USB serial dongle (TS1302 evaluation kit)
    - TCP socket (testing/simulation)

    All transports implement a SPI-like interface since that's the native
    protocol of TROPIC01.
    """

    @abstractmethod
    def open(self) -> None:
        """
        Initialize and open the transport connection.

        Raises:
            ConnectionError: If connection cannot be established
        """
        ...

    @abstractmethod
    def close(self) -> None:
        """
        Close the transport and release all resources.

        Should be safe to call multiple times.
        """
        ...

    @abstractmethod
    def spi_transfer(self, data: bytes, timeout_ms: int = 70) -> bytes:
        """
        Perform full-duplex SPI transfer.

        Simultaneously transmits and receives data. The chip select is
        managed by cs_low() and cs_high() calls.

        Args:
            data: Data bytes to transmit
            timeout_ms: Transfer timeout in milliseconds

        Returns:
            Received data bytes (same length as input)

        Raises:
            TimeoutError: If transfer times out
            TransportError: For other transport failures
        """
        ...

    @abstractmethod
    def cs_low(self) -> None:
        """
        Assert chip select (drive low).

        Must be called before SPI transfer to select the chip.
        """
        ...

    @abstractmethod
    def cs_high(self) -> None:
        """
        Deassert chip select (drive high).

        Must be called after SPI transfer to deselect the chip.
        """
        ...

    @abstractmethod
    def delay_ms(self, ms: int) -> None:
        """
        Platform-specific delay.

        Args:
            ms: Delay duration in milliseconds
        """
        ...

    @abstractmethod
    def random_bytes(self, count: int) -> bytes:
        """
        Generate cryptographically secure random bytes.

        Used for session key generation and other cryptographic operations.

        Args:
            count: Number of random bytes to generate

        Returns:
            Random bytes
        """
        ...

    def wait_for_interrupt(self, timeout_ms: int) -> bool:
        """
        Wait for interrupt pin to signal (optional).

        Not all transports support interrupt pin monitoring. Those that
        don't will use polling instead.

        Args:
            timeout_ms: Maximum time to wait in milliseconds

        Returns:
            True if interrupt received, False if timeout

        Raises:
            NotImplementedError: If transport doesn't support interrupts
        """
        raise NotImplementedError("This transport doesn't support interrupt pin")

    @property
    def supports_interrupt(self) -> bool:
        """Check if this transport supports interrupt pin monitoring."""
        return False

    def __enter__(self) -> 'Transport':
        """Context manager entry - opens the transport."""
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None
    ) -> None:
        """Context manager exit - closes the transport."""
        self.close()
