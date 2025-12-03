"""
HKDF key derivation for libtropic.

Provides HMAC-based Key Derivation Function as specified in TROPIC01 datasheet.
Maps to: lt_hkdf.h

Note: This is a simplified HKDF variant specific to TROPIC01 protocol,
not the full RFC 5869 HKDF.
"""

from typing import Tuple

# HKDF output length (same as HMAC-SHA256)
OUTPUT_LENGTH = 32


def hkdf(
    chaining_key: bytes,
    input_data: bytes,
    num_outputs: int = 2
) -> Tuple[bytes, bytes]:
    """
    Derive keys using HKDF as described in TROPIC01 datasheet.

    This is a simplified HKDF variant that always produces two 32-byte outputs.
    Used internally for session key derivation in the TROPIC01 protocol.

    Algorithm:
        tmp = HMAC-SHA256(chaining_key, input_data)
        output_1 = HMAC-SHA256(tmp, 0x01)
        output_2 = HMAC-SHA256(tmp, output_1 || 0x02)

    Args:
        chaining_key: Chaining key (CK parameter)
        input_data: Input keying material
        num_outputs: Number of outputs (currently ignored, always returns 2)

    Returns:
        Tuple of (output_1, output_2), each 32 bytes

    Example:
        ck = initial_chaining_key
        ikm = shared_secret

        key1, key2 = hkdf(ck, ikm)
        # key1 and key2 are derived 32-byte keys

    Maps to: lt_hkdf()
    """
    raise NotImplementedError()
