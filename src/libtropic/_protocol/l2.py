"""
L2 (Data Link Layer) implementation for TROPIC01 communication.

The L2 layer handles frame construction, CRC calculation, status checking,
and multi-chunk transfers for L3 encrypted commands.
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

from .constants import (
    L1_LEN_MAX,
    L1_TIMEOUT_MS_DEFAULT,
    L2_RESEND_REQ_ID,
    L2_STATUS_CRC_ERR,
    L2_STATUS_GEN_ERR,
    L2_STATUS_HSK_ERR,
    L2_STATUS_NO_RESP,
    L2_STATUS_NO_SESSION,
    L2_STATUS_REQUEST_CONT,
    L2_STATUS_REQUEST_OK,
    L2_STATUS_RESP_DISABLED,
    L2_STATUS_RESULT_CONT,
    L2_STATUS_RESULT_OK,
    L2_STATUS_TAG_ERR,
    L2_STATUS_UNKNOWN_ERR,
)
from .crc16 import add_crc, crc16
from .l1 import L1Error, L1Layer

if TYPE_CHECKING:
    from ..transport.base import Transport


class L2FrameStatus(IntEnum):
    """L2 response status values."""
    REQUEST_OK = L2_STATUS_REQUEST_OK
    RESULT_OK = L2_STATUS_RESULT_OK
    REQUEST_CONT = L2_STATUS_REQUEST_CONT
    RESULT_CONT = L2_STATUS_RESULT_CONT
    RESP_DISABLED = L2_STATUS_RESP_DISABLED
    HSK_ERR = L2_STATUS_HSK_ERR
    NO_SESSION = L2_STATUS_NO_SESSION
    TAG_ERR = L2_STATUS_TAG_ERR
    CRC_ERR = L2_STATUS_CRC_ERR
    UNKNOWN_ERR = L2_STATUS_UNKNOWN_ERR
    GEN_ERR = L2_STATUS_GEN_ERR
    NO_RESP = L2_STATUS_NO_RESP


class L2Error(Exception):
    """Base exception for L2 layer errors."""


class L2CrcError(L2Error):
    """CRC error in received frame."""


class L2StatusError(L2Error):
    """Error status in L2 response."""
    def __init__(self, status: L2FrameStatus, message: str):
        self.status = status
        super().__init__(message)


class L2LengthError(L2Error):
    """Invalid response length."""


@dataclass
class L2Response:
    """
    Parsed L2 response.

    Attributes:
        chip_status: Raw chip status byte (READY, ALARM, STARTUP bits)
        status: L2 frame status code
        data: Response data (without STATUS, LEN, CRC)
    """
    chip_status: int
    status: L2FrameStatus
    data: bytes


class L2Layer:
    """
    L2 (Data Link Layer) for TROPIC01 communication.

    Handles frame construction, CRC calculation/verification, status
    interpretation, and automatic resend on CRC errors.

    L2 Request Frame Format:
        [REQ_ID, REQ_LEN, ...DATA..., CRC_HI, CRC_LO]

    L2 Response Frame Format (as returned by L1):
        [CHIP_STATUS, STATUS, RSP_LEN, ...DATA..., CRC_HI, CRC_LO]

    Status Codes:
        - 0x01: REQUEST_OK - Request executed successfully
        - 0x02: RESULT_OK - Result available
        - 0x03: REQUEST_CONT - More request chunks expected
        - 0x04: RESULT_CONT - More result chunks to read
        - 0x78+: Error codes (HSK_ERR, NO_SESSION, TAG_ERR, etc.)
    """

    # Maximum number of resend attempts on CRC error
    MAX_RESEND_ATTEMPTS = 3

    def __init__(self, transport: "Transport"):
        """
        Initialize L2 layer with transport.

        Args:
            transport: Low-level transport implementation
        """
        self._l1 = L1Layer(transport)
        self._startup_req_sent = False

    @property
    def l1(self) -> L1Layer:
        """Access to underlying L1 layer."""
        return self._l1

    def send(self, req_id: int, data: bytes = b"") -> None:
        """
        Send L2 request frame.

        Constructs a complete L2 frame with CRC and sends via L1.

        Args:
            req_id: Request ID byte
            data: Request data (without REQ_ID, LEN, CRC)
        """
        # Build frame: REQ_ID + LEN + DATA + CRC(2)
        frame_len = 2 + len(data) + 2
        frame = bytearray(frame_len)
        frame[0] = req_id
        frame[1] = len(data)
        frame[2:2 + len(data)] = data

        # Calculate and append CRC
        add_crc(frame)

        self._l1.write(bytes(frame))

    def receive(self, timeout_ms: int = L1_TIMEOUT_MS_DEFAULT) -> L2Response:
        """
        Receive L2 response frame.

        Reads response via L1, verifies CRC, and parses status.
        Automatically retries on CRC errors.

        Args:
            timeout_ms: Timeout in milliseconds

        Returns:
            Parsed L2 response

        Raises:
            L2CrcError: If CRC verification fails after retries
            L2StatusError: If response contains error status
            L2LengthError: If response length is invalid
        """
        response = self._l1.read(max_len=L1_LEN_MAX, timeout_ms=timeout_ms)
        return self._parse_and_verify(response)

    def send_receive(
        self,
        req_id: int,
        data: bytes = b"",
        timeout_ms: int = L1_TIMEOUT_MS_DEFAULT,
    ) -> L2Response:
        """
        Send request and receive response.

        Convenience method for simple request/response exchanges.

        Args:
            req_id: Request ID byte
            data: Request data
            timeout_ms: Timeout in milliseconds

        Returns:
            Parsed L2 response
        """
        self.send(req_id, data)
        return self.receive(timeout_ms)

    def _parse_and_verify(self, frame: bytes) -> L2Response:
        """
        Parse L2 response frame and verify CRC.

        Args:
            frame: Complete L2 response frame from L1

        Returns:
            Parsed L2 response

        Raises:
            L2CrcError: If CRC verification fails
            L2StatusError: If response contains error status
            L2LengthError: If response length is invalid
        """
        if len(frame) < 5:  # CHIP_STATUS + STATUS + LEN + CRC(2) minimum
            raise L2LengthError(f"Response too short: {len(frame)} bytes")

        chip_status = frame[0]
        status_byte = frame[1]
        rsp_len = frame[2]

        # Handle special case for reboot response (erratum workaround)
        if (self._startup_req_sent and
            status_byte == L2_STATUS_REQUEST_OK and
            rsp_len == 0x00 and
            len(frame) >= 4 and
            frame[3] == 0x03):
            # Reboot in progress, CRC may be incomplete
            self._startup_req_sent = False
            return L2Response(
                chip_status=chip_status,
                status=L2FrameStatus(status_byte),
                data=b"",
            )

        # Verify CRC on response (excluding CHIP_STATUS byte)
        frame_without_chip_status = frame[1:]  # STATUS + LEN + DATA + CRC
        if not self._verify_crc(frame_without_chip_status):
            # Try to resend
            for _ in range(self.MAX_RESEND_ATTEMPTS):
                try:
                    response = self._resend_response()
                    if self._verify_crc(response[1:]):
                        return self._parse_verified(response)
                except L1Error:
                    continue
            raise L2CrcError("CRC verification failed after retries")

        return self._parse_verified(frame)

    def _parse_verified(self, frame: bytes) -> L2Response:
        """Parse a CRC-verified frame into L2Response."""
        chip_status = frame[0]
        status_byte = frame[1]
        rsp_len = frame[2]

        try:
            status = L2FrameStatus(status_byte)
        except ValueError:
            raise L2StatusError(
                L2FrameStatus.UNKNOWN_ERR,
                f"Unknown status byte: 0x{status_byte:02X}"
            ) from None

        # Extract data (between LEN and CRC)
        data = frame[3:3 + rsp_len]

        # Check for error statuses
        if status in (L2FrameStatus.REQUEST_OK, L2FrameStatus.RESULT_OK,
                      L2FrameStatus.REQUEST_CONT, L2FrameStatus.RESULT_CONT):
            return L2Response(chip_status=chip_status, status=status, data=data)

        # Map error statuses to exceptions
        error_messages = {
            L2FrameStatus.RESP_DISABLED: "Request is disabled",
            L2FrameStatus.HSK_ERR: "Handshake error",
            L2FrameStatus.NO_SESSION: "No active session",
            L2FrameStatus.TAG_ERR: "Authentication tag error",
            L2FrameStatus.CRC_ERR: "CRC error (reported by device)",
            L2FrameStatus.UNKNOWN_ERR: "Unknown request ID",
            L2FrameStatus.GEN_ERR: "General error",
            L2FrameStatus.NO_RESP: "No response available",
        }
        msg = error_messages.get(status, f"Error status: 0x{status_byte:02X}")
        raise L2StatusError(status, msg)

    def _verify_crc(self, frame: bytes) -> bool:
        """Verify CRC of frame (STATUS + LEN + DATA + CRC)."""
        if len(frame) < 4:
            return False
        rsp_len = frame[1]
        crc_offset = 2 + rsp_len
        if len(frame) < crc_offset + 2:
            return False

        expected_crc = (frame[crc_offset] << 8) | frame[crc_offset + 1]
        calculated_crc = crc16(frame[:crc_offset])
        return expected_crc == calculated_crc

    def _resend_response(self) -> bytes:
        """Request resend of last response."""
        # Send RESEND request
        frame = bytearray(4)  # REQ_ID + LEN + CRC(2)
        frame[0] = L2_RESEND_REQ_ID
        frame[1] = 0  # No data
        add_crc(frame)

        self._l1.write(bytes(frame))
        return self._l1.read()

    def mark_startup_sent(self) -> None:
        """Mark that a startup/reboot request was sent (for erratum workaround)."""
        self._startup_req_sent = True
