"""
L3 (Application Layer) implementation for TROPIC01 communication.

The L3 layer handles encrypted command/response exchange over secure sessions.
Commands and responses are encrypted using AES-256-GCM with session keys
derived during the handshake.

L3 Command Frame Format:
    [CMD_SIZE (2B, little-endian)] [CMD_ID (1B)] [DATA...] [TAG (16B)]

    - CMD_SIZE: Size of CMD_ID + DATA (not including size field or tag)
    - CMD_ID: Command identifier (0x01-0x90)
    - DATA: Command-specific data
    - TAG: AES-GCM authentication tag (appended by encryption)

L3 Response Frame Format:
    [RES_SIZE (2B, little-endian)] [RESULT (1B)] [DATA...] [TAG (16B)]

    - RES_SIZE: Size of RESULT + DATA (not including size field or tag)
    - RESULT: Result code (0x01=OK, 0x02=FAIL, etc.)
    - DATA: Response-specific data
    - TAG: AES-GCM authentication tag (verified by decryption)

Encryption:
    - Key: k_cmd (32 bytes, derived during handshake)
    - IV: cmd_iv (12 bytes, incremented after each command)
    - AAD: empty
    - Plaintext: CMD_ID || DATA
    - Output: CMD_SIZE || ciphertext || TAG

Decryption:
    - Key: k_res (32 bytes, derived during handshake)
    - IV: res_iv (12 bytes, incremented after each response)
    - AAD: empty
    - Ciphertext: everything after RES_SIZE, excluding TAG
    - Output: RESULT || DATA
"""

from typing import TYPE_CHECKING

from .constants import (
    L3_RESULT_COUNTER_INVALID,
    L3_RESULT_FAIL,
    L3_RESULT_HARDWARE_FAIL,
    L3_RESULT_INVALID_CMD,
    L3_RESULT_INVALID_KEY,
    L3_RESULT_OK,
    L3_RESULT_SLOT_EMPTY,
    L3_RESULT_SLOT_EXPIRED,
    L3_RESULT_SLOT_INVALID,
    L3_RESULT_SLOT_NOT_EMPTY,
    L3_RESULT_UNAUTHORIZED,
    L3_RESULT_UPDATE_ERR,
    L3_SIZE_SIZE,
    L3_TAG_SIZE,
)

if TYPE_CHECKING:
    from ..device import SessionState


class L3Error(Exception):
    """Base exception for L3 layer errors."""
    pass


class L3NonceOverflowError(L3Error):
    """IV/nonce counter overflow (would wrap to zero)."""
    pass


class L3ResponseSizeError(L3Error):
    """Invalid response size."""
    pass


class L3ResultError(L3Error):
    """L3 command returned an error result."""
    def __init__(self, result_code: int, message: str):
        self.result_code = result_code
        super().__init__(message)


def increment_iv(iv: bytearray) -> None:
    """
    Increment the 12-byte IV counter.

    The IV uses a 32-bit little-endian counter in the first 4 bytes.
    Raises L3NonceOverflowError if counter would overflow.

    Args:
        iv: 12-byte IV to increment in-place

    Raises:
        L3NonceOverflowError: If counter would wrap to zero
    """
    # Extract 32-bit counter from first 4 bytes (little-endian)
    counter = iv[0] | (iv[1] << 8) | (iv[2] << 16) | (iv[3] << 24)

    # Check for overflow
    if counter == 0xFFFFFFFF:
        raise L3NonceOverflowError("IV counter overflow - session must be restarted")

    # Increment
    counter += 1

    # Write back (little-endian)
    iv[0] = counter & 0xFF
    iv[1] = (counter >> 8) & 0xFF
    iv[2] = (counter >> 16) & 0xFF
    iv[3] = (counter >> 24) & 0xFF


def encrypt_command(session: "SessionState", cmd_id: int, data: bytes = b"") -> bytes:
    """
    Encrypt L3 command for transmission.

    Builds and encrypts an L3 command frame:
    1. Constructs plaintext: CMD_ID || DATA
    2. Encrypts with AES-GCM using k_cmd and cmd_iv
    3. Prepends CMD_SIZE (little-endian)
    4. Increments cmd_iv

    Args:
        session: Active session state with keys and IVs
        cmd_id: Command identifier byte
        data: Command data (may be empty)

    Returns:
        Complete L3 command frame: CMD_SIZE || ciphertext || TAG

    Raises:
        L3NonceOverflowError: If IV counter would overflow
    """
    from .._cal import AesGcmEncryptContext

    # Build plaintext: CMD_ID || DATA
    plaintext = bytes([cmd_id]) + data

    # CMD_SIZE is the size of plaintext (CMD_ID + DATA)
    cmd_size = len(plaintext)

    # Encrypt with AES-GCM
    # Returns ciphertext || tag
    with AesGcmEncryptContext(session.k_cmd) as ctx:
        ciphertext_with_tag = ctx.encrypt(
            iv=bytes(session.cmd_iv),
            plaintext=plaintext,
            aad=b""  # No additional authenticated data
        )

    # Increment command IV for next command
    increment_iv(session.cmd_iv)

    # Build frame: CMD_SIZE (2B little-endian) || ciphertext || tag
    frame = bytearray(L3_SIZE_SIZE + len(ciphertext_with_tag))
    frame[0] = cmd_size & 0xFF
    frame[1] = (cmd_size >> 8) & 0xFF
    frame[L3_SIZE_SIZE:] = ciphertext_with_tag

    return bytes(frame)


def decrypt_response(session: "SessionState", frame: bytes) -> tuple[int, bytes]:
    """
    Decrypt L3 response from device.

    Parses and decrypts an L3 response frame:
    1. Extracts RES_SIZE from first 2 bytes
    2. Decrypts ciphertext+tag with AES-GCM using k_res and res_iv
    3. Extracts RESULT code and DATA from plaintext
    4. Increments res_iv
    5. Raises exception if RESULT indicates error

    Args:
        session: Active session state with keys and IVs
        frame: Complete L3 response frame from device

    Returns:
        Tuple of (result_code, data)

    Raises:
        L3ResponseSizeError: If frame is malformed
        L3NonceOverflowError: If IV counter would overflow
        L3ResultError: If RESULT code indicates an error
        CryptoError: If decryption/authentication fails
    """
    from .._cal import AesGcmDecryptContext

    # Minimum frame size: RES_SIZE(2) + RESULT(1) + TAG(16)
    min_size = L3_SIZE_SIZE + 1 + L3_TAG_SIZE
    if len(frame) < min_size:
        raise L3ResponseSizeError(f"Response too short: {len(frame)} bytes (minimum {min_size})")

    # Extract RES_SIZE (little-endian)
    res_size = frame[0] | (frame[1] << 8)

    # Validate size
    # Expected frame length: RES_SIZE(2) + ciphertext(res_size) + TAG(16)
    expected_len = L3_SIZE_SIZE + res_size + L3_TAG_SIZE
    if len(frame) < expected_len:
        raise L3ResponseSizeError(
            f"Response size mismatch: frame={len(frame)}, expected={expected_len} "
            f"(res_size={res_size})"
        )

    # Extract ciphertext + tag (everything after RES_SIZE)
    ciphertext_with_tag = frame[L3_SIZE_SIZE:L3_SIZE_SIZE + res_size + L3_TAG_SIZE]

    # Decrypt with AES-GCM
    with AesGcmDecryptContext(session.k_res) as ctx:
        plaintext = ctx.decrypt(
            iv=bytes(session.res_iv),
            ciphertext=ciphertext_with_tag,
            aad=b""  # No additional authenticated data
        )

    # Increment response IV for next response
    increment_iv(session.res_iv)

    # Extract RESULT and DATA from plaintext
    if len(plaintext) < 1:
        raise L3ResponseSizeError("Decrypted response has no result byte")

    result_code = plaintext[0]
    data = plaintext[1:] if len(plaintext) > 1 else b""

    # Check result code and raise appropriate exception
    _check_result(result_code)

    return result_code, data


def _check_result(result_code: int) -> None:
    """
    Check L3 result code and raise exception if error.

    Args:
        result_code: Result byte from decrypted response

    Raises:
        L3ResultError: If result code indicates an error
    """
    if result_code == L3_RESULT_OK:
        return

    # Map result codes to error messages
    error_messages = {
        L3_RESULT_FAIL: "Command failed",
        L3_RESULT_UNAUTHORIZED: "Operation not authorized (UAP)",
        L3_RESULT_INVALID_CMD: "Invalid command ID",
        L3_RESULT_SLOT_EMPTY: "Slot is empty",
        L3_RESULT_SLOT_INVALID: "Invalid slot index",
        L3_RESULT_INVALID_KEY: "Invalid key or wrong key type",
        L3_RESULT_SLOT_NOT_EMPTY: "Slot is not empty",
        L3_RESULT_SLOT_EXPIRED: "Slot has expired",
        L3_RESULT_UPDATE_ERR: "Update operation failed",
        L3_RESULT_COUNTER_INVALID: "Counter not initialized or at zero",
        L3_RESULT_HARDWARE_FAIL: "Hardware failure",
    }

    message = error_messages.get(result_code, f"Unknown result code: 0x{result_code:02X}")
    raise L3ResultError(result_code, message)


def result_code_to_exception(result_code: int) -> Exception:
    """
    Convert L3 result code to appropriate exception.

    This allows higher-level code to catch specific exception types.

    Args:
        result_code: L3 result code

    Returns:
        Appropriate exception instance
    """
    from ..enums import ReturnCode
    from ..exceptions import (
        CounterInvalidError,
        HardwareError,
        InvalidKeyError,
        SlotEmptyError,
        SlotExpiredError,
        SlotInvalidError,
        SlotNotEmptyError,
        TropicError,
        UnauthorizedError,
    )

    exception_map = {
        L3_RESULT_FAIL: TropicError(ReturnCode.L3_FAIL, "Command failed"),
        L3_RESULT_UNAUTHORIZED: UnauthorizedError(
            ReturnCode.L3_UNAUTHORIZED, "Operation not authorized"
        ),
        L3_RESULT_INVALID_CMD: TropicError(ReturnCode.L3_INVALID_CMD, "Invalid command ID"),
        L3_RESULT_SLOT_EMPTY: SlotEmptyError(ReturnCode.L3_SLOT_EMPTY, "Slot is empty"),
        L3_RESULT_SLOT_INVALID: SlotInvalidError(
            ReturnCode.L3_SLOT_INVALID, "Invalid slot index"
        ),
        L3_RESULT_INVALID_KEY: InvalidKeyError(
            ReturnCode.L3_INVALID_KEY, "Invalid key or wrong key type"
        ),
        L3_RESULT_SLOT_NOT_EMPTY: SlotNotEmptyError(
            ReturnCode.L3_SLOT_NOT_EMPTY, "Slot is not empty"
        ),
        L3_RESULT_SLOT_EXPIRED: SlotExpiredError(
            ReturnCode.L3_SLOT_EXPIRED, "Slot has expired"
        ),
        L3_RESULT_UPDATE_ERR: TropicError(ReturnCode.L3_UPDATE_ERR, "Update operation failed"),
        L3_RESULT_COUNTER_INVALID: CounterInvalidError(
            ReturnCode.L3_COUNTER_INVALID, "Counter not initialized or at zero"
        ),
        L3_RESULT_HARDWARE_FAIL: HardwareError(ReturnCode.L3_HARDWARE_FAIL, "Hardware failure"),
    }

    return exception_map.get(
        result_code,
        TropicError(ReturnCode.L3_RESULT_UNKNOWN, f"Unknown L3 result: 0x{result_code:02X}")
    )
