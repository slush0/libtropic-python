"""
AES-GCM encryption/decryption for libtropic.

Provides authenticated encryption using AES-GCM mode.
Maps to: lt_aesgcm.h
"""

from typing import Optional

# AES-GCM tag size used by TROPIC01 L3 protocol
L3_TAG_SIZE = 16


class AesGcmEncryptContext:
    """
    AES-GCM encryption context.

    Provides authenticated encryption with associated data (AEAD).
    Context must be initialized with a key before use.

    Example:
        ctx = AesGcmEncryptContext()
        ctx.init(key)
        ciphertext = ctx.encrypt(iv, plaintext, aad)
        ctx.deinit()

    Or using context manager:
        with AesGcmEncryptContext(key) as ctx:
            ciphertext = ctx.encrypt(iv, plaintext, aad)

    Maps to: gcm_ctx (encrypt) from trezor_crypto
    """

    def __init__(self, key: Optional[bytes] = None) -> None:
        """
        Create AES-GCM encryption context.

        Args:
            key: Optional 16/24/32-byte AES key. If provided, calls init().

        Maps to: lt_aesgcm_encrypt_init() if key provided
        """
        raise NotImplementedError()

    def init(self, key: bytes) -> None:
        """
        Initialize context with encryption key.

        Args:
            key: 16-byte (AES-128), 24-byte (AES-192), or 32-byte (AES-256) key

        Raises:
            CryptoError: If initialization fails
            ParamError: If key length is invalid

        Maps to: lt_aesgcm_encrypt_init()
        """
        raise NotImplementedError()

    def encrypt(
        self,
        iv: bytes,
        plaintext: bytes,
        aad: Optional[bytes] = None
    ) -> bytes:
        """
        Encrypt data with authentication.

        Args:
            iv: Initialization vector (typically 12 bytes for GCM)
            plaintext: Data to encrypt
            aad: Additional authenticated data (optional, not encrypted but authenticated)

        Returns:
            Ciphertext with appended authentication tag (plaintext_len + 16 bytes)

        Raises:
            CryptoError: If encryption fails
            ParamError: If context not initialized

        Maps to: lt_aesgcm_encrypt()
        """
        raise NotImplementedError()

    def deinit(self) -> None:
        """
        Deinitialize and clear context.

        Securely clears key material from memory.

        Maps to: lt_aesgcm_encrypt_deinit()
        """
        raise NotImplementedError()

    def __enter__(self) -> 'AesGcmEncryptContext':
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        """Context manager exit - ensures deinit is called."""
        self.deinit()


class AesGcmDecryptContext:
    """
    AES-GCM decryption context.

    Provides authenticated decryption with associated data (AEAD).
    Context must be initialized with a key before use.

    Example:
        ctx = AesGcmDecryptContext()
        ctx.init(key)
        plaintext = ctx.decrypt(iv, ciphertext, aad)
        ctx.deinit()

    Or using context manager:
        with AesGcmDecryptContext(key) as ctx:
            plaintext = ctx.decrypt(iv, ciphertext, aad)

    Maps to: gcm_ctx (decrypt) from trezor_crypto
    """

    def __init__(self, key: Optional[bytes] = None) -> None:
        """
        Create AES-GCM decryption context.

        Args:
            key: Optional 16/24/32-byte AES key. If provided, calls init().

        Maps to: lt_aesgcm_decrypt_init() if key provided
        """
        raise NotImplementedError()

    def init(self, key: bytes) -> None:
        """
        Initialize context with decryption key.

        Args:
            key: 16-byte (AES-128), 24-byte (AES-192), or 32-byte (AES-256) key

        Raises:
            CryptoError: If initialization fails
            ParamError: If key length is invalid

        Maps to: lt_aesgcm_decrypt_init()
        """
        raise NotImplementedError()

    def decrypt(
        self,
        iv: bytes,
        ciphertext: bytes,
        aad: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt data and verify authentication tag.

        Args:
            iv: Initialization vector (must match encryption IV)
            ciphertext: Encrypted data with appended authentication tag
            aad: Additional authenticated data (must match encryption AAD)

        Returns:
            Decrypted plaintext (ciphertext_len - 16 bytes)

        Raises:
            CryptoError: If decryption fails or authentication tag is invalid
            ParamError: If context not initialized or ciphertext too short

        Maps to: lt_aesgcm_decrypt()
        """
        raise NotImplementedError()

    def deinit(self) -> None:
        """
        Deinitialize and clear context.

        Securely clears key material from memory.

        Maps to: lt_aesgcm_decrypt_deinit()
        """
        raise NotImplementedError()

    def __enter__(self) -> 'AesGcmDecryptContext':
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        """Context manager exit - ensures deinit is called."""
        self.deinit()

