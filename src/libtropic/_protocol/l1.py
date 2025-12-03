"""
L1 (Physical Layer) implementation for TROPIC01 communication.

The L1 layer handles low-level SPI transfers with the TROPIC01 chip,
including chip status polling and response retrieval.
"""

from typing import TYPE_CHECKING

from .constants import (
    L1_CHIP_MODE_ALARM,
    L1_CHIP_MODE_READY,
    L1_CHIP_MODE_STARTUP,
    L1_GET_RESPONSE_REQ_ID,
    L1_LEN_MAX,
    L1_READ_MAX_TRIES,
    L1_READ_RETRY_DELAY_MS,
    L1_TIMEOUT_MS_DEFAULT,
)

if TYPE_CHECKING:
    from ..transport.base import Transport


class L1Error(Exception):
    """Base exception for L1 layer errors."""
    pass


class L1ChipBusyError(L1Error):
    """Chip is busy and not responding after max retries."""
    pass


class L1ChipAlarmError(L1Error):
    """Chip is in ALARM mode."""
    pass


class L1DataLengthError(L1Error):
    """Invalid data length in response."""
    pass


class L1SpiError(L1Error):
    """SPI communication error."""
    pass


class L1Layer:
    """
    L1 (Physical Layer) for TROPIC01 communication.

    Handles low-level SPI transfers, chip status polling, and response
    retrieval. The L1 layer manages the chip select signal and interprets
    chip status bytes.

    Chip Status Byte:
        - Bit 0 (READY): Chip is ready to accept commands
        - Bit 1 (ALARM): Chip is in alarm mode (security event)
        - Bit 2 (STARTUP): Chip is in startup/maintenance mode

    Device Modes (interpreted from chip status):
        - APPLICATION: READY=1, ALARM=0, STARTUP=0
        - MAINTENANCE: READY=1, ALARM=0, STARTUP=1
        - ALARM: ALARM=1 (other bits ignored)
    """

    def __init__(self, transport: "Transport"):
        """
        Initialize L1 layer with transport.

        Args:
            transport: Low-level transport implementation (USB dongle, SPI, etc.)
        """
        self._transport = transport
        # Buffer for L2 frames (pre-allocated for performance)
        self._buffer = bytearray(L1_LEN_MAX)

    def read(
        self,
        max_len: int = L1_LEN_MAX,
        timeout_ms: int = L1_TIMEOUT_MS_DEFAULT,
    ) -> bytes:
        """
        Read L2 response frame from TROPIC01.

        Polls the chip until it's ready and has a response, then reads
        the complete L2 frame.

        Args:
            max_len: Maximum expected response length
            timeout_ms: Transfer timeout in milliseconds

        Returns:
            Complete L2 response frame (including chip_status byte at offset 0)

        Raises:
            L1ChipAlarmError: If chip is in ALARM mode
            L1ChipBusyError: If chip doesn't respond after max retries
            L1DataLengthError: If response length is invalid
            L1SpiError: If SPI transfer fails
        """
        tries_remaining = L1_READ_MAX_TRIES

        while tries_remaining > 0:
            tries_remaining -= 1

            # Send GET_RESPONSE request ID to read chip status
            self._buffer[0] = L1_GET_RESPONSE_REQ_ID

            # Transfer one byte to get CHIP_STATUS
            try:
                self._transport.cs_low()
                response = self._transport.spi_transfer(bytes([self._buffer[0]]), timeout_ms)
                self._buffer[0] = response[0]
            except Exception as e:
                self._transport.cs_high()
                raise L1SpiError(f"SPI transfer failed: {e}") from e

            chip_status = self._buffer[0]

            # Check ALARM bit first (highest priority)
            if chip_status & L1_CHIP_MODE_ALARM:
                self._transport.cs_high()
                raise L1ChipAlarmError(f"Chip in ALARM mode (status=0x{chip_status:02X})")

            # Check if chip is ready
            if chip_status & L1_CHIP_MODE_READY:
                # Read STATUS and RSP_LEN bytes
                try:
                    response = self._transport.spi_transfer(bytes(2), timeout_ms)
                    self._buffer[1] = response[0]  # STATUS
                    self._buffer[2] = response[1]  # RSP_LEN
                except Exception as e:
                    self._transport.cs_high()
                    raise L1SpiError(f"SPI transfer failed: {e}") from e

                # Check for "no response available" (0xFF in STATUS)
                if self._buffer[1] == 0xFF:
                    self._transport.cs_high()
                    self._transport.delay_ms(L1_READ_RETRY_DELAY_MS)
                    continue

                # Calculate remaining bytes to read (DATA + CRC)
                rsp_len = self._buffer[2]
                remaining = rsp_len + 2  # DATA + 2 bytes CRC

                if remaining > (L1_LEN_MAX - 3):  # Already read 3 bytes
                    self._transport.cs_high()
                    raise L1DataLengthError(f"Response too long: {remaining} bytes")

                # Read remaining data
                if remaining > 0:
                    try:
                        response = self._transport.spi_transfer(bytes(remaining), timeout_ms)
                        self._buffer[3:3 + remaining] = response
                    except Exception as e:
                        self._transport.cs_high()
                        raise L1SpiError(f"SPI transfer failed: {e}") from e

                self._transport.cs_high()

                # Return complete frame (CHIP_STATUS + STATUS + LEN + DATA + CRC)
                total_len = 3 + remaining
                return bytes(self._buffer[:total_len])

            else:
                # Chip not ready - release CS and retry after delay
                self._transport.cs_high()

                # Use longer delay if in startup mode (no INT pin)
                self._transport.delay_ms(L1_READ_RETRY_DELAY_MS)

        raise L1ChipBusyError(f"Chip busy after {L1_READ_MAX_TRIES} retries")

    def write(
        self,
        data: bytes,
        timeout_ms: int = L1_TIMEOUT_MS_DEFAULT,
    ) -> None:
        """
        Write L2 request frame to TROPIC01.

        Args:
            data: Complete L2 request frame (REQ_ID + LEN + DATA + CRC)
            timeout_ms: Transfer timeout in milliseconds

        Raises:
            L1SpiError: If SPI transfer fails
        """
        if len(data) > L1_LEN_MAX:
            raise L1DataLengthError(f"Request too long: {len(data)} bytes")

        try:
            self._transport.cs_low()
            self._transport.spi_transfer(data, timeout_ms)
            self._transport.cs_high()
        except Exception as e:
            try:
                self._transport.cs_high()
            except Exception:
                pass
            raise L1SpiError(f"SPI transfer failed: {e}") from e

    def get_chip_status(self) -> int:
        """
        Read current chip status byte.

        Returns:
            Chip status byte (READY, ALARM, STARTUP bits)

        Raises:
            L1SpiError: If SPI transfer fails
        """
        try:
            self._transport.cs_low()
            response = self._transport.spi_transfer(bytes([L1_GET_RESPONSE_REQ_ID]))
            self._transport.cs_high()
            return response[0]
        except Exception as e:
            try:
                self._transport.cs_high()
            except Exception:
                pass
            raise L1SpiError(f"Failed to read chip status: {e}") from e

    def is_in_alarm_mode(self) -> bool:
        """Check if chip is in ALARM mode."""
        status = self.get_chip_status()
        return bool(status & L1_CHIP_MODE_ALARM)

    def is_in_startup_mode(self) -> bool:
        """Check if chip is in STARTUP (maintenance) mode."""
        status = self.get_chip_status()
        return bool(status & L1_CHIP_MODE_STARTUP) and not bool(status & L1_CHIP_MODE_ALARM)

    def is_ready(self) -> bool:
        """Check if chip is ready to accept commands."""
        status = self.get_chip_status()
        return bool(status & L1_CHIP_MODE_READY)
