"""
Exception hierarchy for libtropic Python bindings.

Provides Pythonic error handling for TROPIC01 operations.
"""


from .enums import ReturnCode


class TropicError(Exception):
    """
    Base exception for all libtropic errors.

    Attributes:
        code: The ReturnCode from the underlying operation
        message: Human-readable error description
    """

    def __init__(self, code: ReturnCode, message: str = ""):
        self.code = code
        self.message = message
        super().__init__(f"{code.name}: {message}" if message else code.name)

    @classmethod
    def from_code(cls, code: ReturnCode, message: str = "") -> 'TropicError':
        """
        Create appropriate exception subclass based on return code.

        Args:
            code: Return code from libtropic operation
            message: Optional additional context

        Returns:
            Appropriate TropicError subclass instance
        """
        # Map return codes to specific exception types
        exception_map = {
            ReturnCode.HOST_NO_SESSION: NoSessionError,
            ReturnCode.PARAM_ERR: ParamError,
            ReturnCode.CRYPTO_ERR: CryptoError,
            ReturnCode.L1_CHIP_ALARM_MODE: DeviceAlarmError,
            ReturnCode.L3_UNAUTHORIZED: UnauthorizedError,
            ReturnCode.L3_SLOT_EMPTY: SlotEmptyError,
            ReturnCode.L3_SLOT_NOT_EMPTY: SlotNotEmptyError,
            ReturnCode.L3_SLOT_EXPIRED: SlotExpiredError,
            ReturnCode.L3_SLOT_INVALID: SlotInvalidError,
            ReturnCode.L3_INVALID_KEY: InvalidKeyError,
            ReturnCode.L3_COUNTER_INVALID: CounterInvalidError,
            ReturnCode.L3_HARDWARE_FAIL: HardwareError,
            ReturnCode.L2_HSK_ERR: HandshakeError,
            ReturnCode.L2_TAG_ERR: AuthenticationError,
            ReturnCode.L2_CRC_ERR: CrcError,
            ReturnCode.CERT_STORE_INVALID: CertificateError,
            ReturnCode.CERT_ITEM_NOT_FOUND: CertificateError,
            ReturnCode.REBOOT_UNSUCCESSFUL: RebootError,
        }

        exception_class = exception_map.get(code, TropicError)
        return exception_class(code, message)


class NoSessionError(TropicError):
    """Raised when operation requires an active secure session but none exists."""


class ParamError(TropicError):
    """Raised for invalid parameter values."""


class CryptoError(TropicError):
    """Raised for cryptographic operation failures."""


class DeviceAlarmError(TropicError):
    """Raised when device enters alarm mode (security event)."""


class UnauthorizedError(TropicError):
    """Raised when operation is not permitted (insufficient privileges)."""


class SlotError(TropicError):
    """Base class for slot-related errors."""


class SlotEmptyError(SlotError):
    """Raised when accessing an empty slot that should contain data."""


class SlotNotEmptyError(SlotError):
    """Raised when writing to a slot that already contains data."""


class SlotExpiredError(SlotError):
    """Raised when accessing an expired flash slot."""


class SlotInvalidError(SlotError):
    """Raised when slot content is invalidated."""


class InvalidKeyError(TropicError):
    """Raised when key in slot is invalid or corrupted."""


class CounterInvalidError(TropicError):
    """Raised when monotonic counter is disabled, locked, or at zero."""


class HardwareError(TropicError):
    """Raised when a hardware error occurs during write operation."""


class HandshakeError(TropicError):
    """Raised when secure session handshake fails."""


class AuthenticationError(TropicError):
    """Raised when message authentication (MAC/tag) fails."""


class CrcError(TropicError):
    """Raised when CRC check fails on communication."""


class CertificateError(TropicError):
    """Raised for certificate store or validation errors."""


class RebootError(TropicError):
    """Raised when reboot to requested mode fails."""


class TransportError(Exception):
    """
    Raised for transport layer errors (SPI, USB, etc.).

    This is separate from TropicError as it's not a device-level error.
    """


class TimeoutError(TransportError):
    """Raised when transport operation times out."""


class ConnectionError(TransportError):
    """Raised when transport connection fails."""
