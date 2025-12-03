"""
Secure memory zeroing for libtropic.

Provides secure memory wiping that won't be optimized away by the compiler.
Maps to: lt_secure_memzero.h

Note: In Python, true secure memory zeroing is challenging due to:
- Immutable bytes objects
- Garbage collection
- String interning
- Memory copying by the interpreter

This module provides best-effort zeroing for mutable types (bytearray).
For security-critical applications, consider using PyNaCl or similar
libraries that provide proper secure memory handling.
"""


def secure_memzero(buffer: bytearray) -> None:
    """
    Securely overwrite memory with zeros.

    Attempts to securely zero memory in a way that won't be optimized
    away. Works only with mutable bytearray objects.

    For immutable bytes objects, this function cannot help - the original
    data remains in memory until garbage collected.

    Args:
        buffer: Mutable bytearray to zero

    Raises:
        TypeError: If buffer is not a bytearray

    Example:
        secret = bytearray(b"sensitive data")
        # ... use secret ...
        secure_memzero(secret)  # Wipe when done

    Note:
        For truly secure memory handling in Python, consider:
        - Using PyNaCl's sodium.memzero()
        - Keeping secrets in the secure element (TROPIC01) instead of host memory

    Maps to: lt_secure_memzero()
    """
    if not isinstance(buffer, bytearray):
        raise TypeError(f"Expected bytearray, got {type(buffer).__name__}")

    # Zero each byte in the buffer
    for i in range(len(buffer)):
        buffer[i] = 0
