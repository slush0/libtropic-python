"""
HMAC-SHA256 message authentication for libtropic.

Provides keyed-hash message authentication code using SHA-256.
Maps to: lt_hmac_sha256.h
"""

import hashlib
import hmac

# HMAC-SHA256 output length in bytes
HASH_LENGTH = 32


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256 of data with given key.

    HMAC provides message authentication - verifies both data integrity
    and authenticity using a shared secret key.

    Args:
        key: Secret key (any length, but >= 32 bytes recommended)
        data: Message data to authenticate

    Returns:
        32-byte HMAC-SHA256 authentication tag

    Example:
        tag = hmac_sha256(secret_key, message)

        # Verify (constant-time comparison recommended):
        expected_tag = hmac_sha256(secret_key, received_message)
        if tag == expected_tag:
            print("Message authentic")

    Maps to: lt_hmac_sha256()
    """
    return hmac.new(key, data, hashlib.sha256).digest()
