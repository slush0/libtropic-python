"""
Crypto Abstraction Layer (CAL) for libtropic.

This is a PRIVATE module providing host-side cryptographic primitives
used internally by the libtropic protocol implementation.

NOT part of the public API - do not import from application code.

These primitives are used for:
- Session encryption (AES-GCM)
- Session key exchange (X25519)
- Key derivation (HKDF, HMAC-SHA256)
- Protocol hashing (SHA256)

This mirrors the CAL in libtropic-upstream/cal/ which provides
pluggable crypto backends (trezor_crypto, mbedtls_v4).
"""

# AES-GCM
from .aesgcm import AesGcmDecryptContext, AesGcmEncryptContext, L3_TAG_SIZE

# SHA-256
from .sha256 import DIGEST_LENGTH as SHA256_DIGEST_LENGTH
from .sha256 import Sha256Context, sha256

# HMAC-SHA256
from .hmac_sha256 import HASH_LENGTH as HMAC_SHA256_HASH_LENGTH
from .hmac_sha256 import hmac_sha256

# X25519
from .x25519 import KEY_SIZE as X25519_KEY_SIZE
from .x25519 import x25519, x25519_scalarmult_base

# HKDF
from .hkdf import OUTPUT_LENGTH as HKDF_OUTPUT_LENGTH
from .hkdf import hkdf

# Memory
from .memzero import secure_memzero

__all__ = [
    # AES-GCM
    "AesGcmEncryptContext",
    "AesGcmDecryptContext",
    "L3_TAG_SIZE",
    # SHA-256
    "Sha256Context",
    "sha256",
    "SHA256_DIGEST_LENGTH",
    # HMAC-SHA256
    "hmac_sha256",
    "HMAC_SHA256_HASH_LENGTH",
    # X25519
    "x25519",
    "x25519_scalarmult_base",
    "X25519_KEY_SIZE",
    # HKDF
    "hkdf",
    "HKDF_OUTPUT_LENGTH",
    # Memory
    "secure_memzero",
]
