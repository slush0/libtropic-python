"""
AES-GCM encryption/decryption for libtropic.

Provides authenticated encryption using AES-GCM mode.
Maps to: lt_aesgcm.h
"""

from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .memzero import secure_memzero

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
        self._aesgcm: Optional[AESGCM] = None
        self._key: Optional[bytearray] = None

        if key is not None:
            self.init(key)

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
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Invalid key length: {len(key)}. Must be 16, 24, or 32 bytes.")

        # Store key in mutable buffer for secure clearing later
        self._key = bytearray(key)
        self._aesgcm = AESGCM(bytes(self._key))

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
        if self._aesgcm is None:
            raise RuntimeError("Context not initialized. Call init() first.")

        # cryptography library appends tag automatically
        return self._aesgcm.encrypt(iv, plaintext, aad)

    def deinit(self) -> None:
        """
        Deinitialize and clear context.

        Securely clears key material from memory.

        Maps to: lt_aesgcm_encrypt_deinit()
        """
        if self._key is not None:
            secure_memzero(self._key)
            self._key = None
        self._aesgcm = None

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
        self._aesgcm: Optional[AESGCM] = None
        self._key: Optional[bytearray] = None

        if key is not None:
            self.init(key)

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
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Invalid key length: {len(key)}. Must be 16, 24, or 32 bytes.")

        # Store key in mutable buffer for secure clearing later
        self._key = bytearray(key)
        self._aesgcm = AESGCM(bytes(self._key))

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
        if self._aesgcm is None:
            raise RuntimeError("Context not initialized. Call init() first.")

        # cryptography library expects ciphertext with appended tag
        # and raises InvalidTag on authentication failure
        return self._aesgcm.decrypt(iv, ciphertext, aad)

    def deinit(self) -> None:
        """
        Deinitialize and clear context.

        Securely clears key material from memory.

        Maps to: lt_aesgcm_decrypt_deinit()
        """
        if self._key is not None:
            secure_memzero(self._key)
            self._key = None
        self._aesgcm = None

    def __enter__(self) -> 'AesGcmDecryptContext':
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        """Context manager exit - ensures deinit is called."""
        self.deinit()
