"""
SHA-256 hash functions for libtropic.

Provides incremental SHA-256 hashing.
Maps to: lt_sha256.h
"""

# SHA-256 digest length in bytes
DIGEST_LENGTH = 32


class Sha256Context:
    """
    SHA-256 hash context.

    Provides incremental hashing - data can be added in chunks
    before finalizing to get the digest.

    Example:
        ctx = Sha256Context()
        ctx.start()
        ctx.update(b"Hello, ")
        ctx.update(b"World!")
        digest = ctx.finish()

    Or one-shot:
        digest = sha256(b"Hello, World!")

    Maps to: Hasher with HASHER_SHA2 from trezor_crypto
    """

    def __init__(self) -> None:
        """
        Create SHA-256 context.

        Maps to: lt_sha256_init()
        """
        raise NotImplementedError()

    def start(self) -> None:
        """
        Start/reset the hash computation.

        Must be called before update() to initialize internal state.
        Can be called again to reset and reuse the context.

        Maps to: lt_sha256_start()
        """
        raise NotImplementedError()

    def update(self, data: bytes) -> None:
        """
        Add data to the hash computation.

        Can be called multiple times to add data incrementally.

        Args:
            data: Bytes to add to the hash

        Raises:
            ParamError: If start() was not called

        Maps to: lt_sha256_update()
        """
        raise NotImplementedError()

    def finish(self) -> bytes:
        """
        Finalize and return the hash digest.

        Returns:
            32-byte SHA-256 digest

        Raises:
            ParamError: If start() was not called

        Maps to: lt_sha256_finish()
        """
        raise NotImplementedError()


def sha256(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of data in one shot.

    Convenience function for hashing data that fits in memory.

    Args:
        data: Bytes to hash

    Returns:
        32-byte SHA-256 digest

    Example:
        digest = sha256(b"Hello, World!")
    """
    raise NotImplementedError()
