"""
Cryptographic operations module for libtropic.

Provides high-level cryptographic operations that execute on the
TROPIC01 secure element. Keys never leave the chip.

Available classes:
- EccKeys: ECC key generation, storage, and signing (P256, Ed25519)
- RandomGenerator: Hardware random number generation

Note: Host-side crypto primitives used by the protocol (AES-GCM, X25519, etc.)
are in the internal `_cal` module and not part of the public API.
"""

from .ecc import EccKeys
from .random import RandomGenerator

__all__ = [
    "EccKeys",
    "RandomGenerator",
]
