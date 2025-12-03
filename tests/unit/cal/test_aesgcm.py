"""
Unit tests for AES-GCM encryption/decryption.

Tests the _cal.aesgcm module using Wycheproof test vectors.
"""

import pytest

from libtropic._cal import AesGcmDecryptContext, AesGcmEncryptContext, L3_TAG_SIZE

from .conftest import generate_aesgcm_vectors


class TestAesGcmEncryptContext:
    """Tests for AesGcmEncryptContext."""

    def test_init_with_key(self) -> None:
        """Test context initialization with key."""
        key = bytes.fromhex("00000000000000000000000000000000")
        ctx = AesGcmEncryptContext(key)
        assert ctx is not None

    def test_init_without_key(self) -> None:
        """Test context initialization without key."""
        ctx = AesGcmEncryptContext()
        assert ctx is not None

    def test_explicit_init(self) -> None:
        """Test explicit init() call."""
        key = bytes.fromhex("00000000000000000000000000000000")
        ctx = AesGcmEncryptContext()
        ctx.init(key)

    def test_context_manager(self) -> None:
        """Test context manager usage."""
        key = bytes.fromhex("00000000000000000000000000000000")
        with AesGcmEncryptContext(key) as ctx:
            assert ctx is not None

    def test_encrypt_basic(self) -> None:
        """Test basic encryption."""
        key = bytes.fromhex("00000000000000000000000000000000")
        iv = bytes.fromhex("000000000000000000000000")
        plaintext = bytes.fromhex("00000000000000000000000000000000")

        with AesGcmEncryptContext(key) as ctx:
            ciphertext = ctx.encrypt(iv, plaintext)

        # Ciphertext should be plaintext + tag
        assert len(ciphertext) == len(plaintext) + L3_TAG_SIZE

    def test_encrypt_with_aad(self) -> None:
        """Test encryption with additional authenticated data."""
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        iv = bytes.fromhex("cafebabefacedbaddecaf888")
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        )

        with AesGcmEncryptContext(key) as ctx:
            ciphertext = ctx.encrypt(iv, plaintext, aad)

        assert len(ciphertext) == len(plaintext) + L3_TAG_SIZE

    def test_encrypt_empty_plaintext(self) -> None:
        """Test encryption with empty plaintext (authentication only)."""
        key = bytes.fromhex("bedcfb5a011ebc84600fcb296c15af0d")
        iv = bytes.fromhex("438a547a94ea88dce46c6c85")

        with AesGcmEncryptContext(key) as ctx:
            ciphertext = ctx.encrypt(iv, b"")

        # Should only contain tag
        assert len(ciphertext) == L3_TAG_SIZE


class TestAesGcmDecryptContext:
    """Tests for AesGcmDecryptContext."""

    def test_init_with_key(self) -> None:
        """Test context initialization with key."""
        key = bytes.fromhex("00000000000000000000000000000000")
        ctx = AesGcmDecryptContext(key)
        assert ctx is not None

    def test_context_manager(self) -> None:
        """Test context manager usage."""
        key = bytes.fromhex("00000000000000000000000000000000")
        with AesGcmDecryptContext(key) as ctx:
            assert ctx is not None

    def test_decrypt_basic(self) -> None:
        """Test basic decryption."""
        key = bytes.fromhex("00000000000000000000000000000000")
        iv = bytes.fromhex("000000000000000000000000")
        ciphertext = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
        tag = bytes.fromhex("ab6e47d42cec13bdf53a67b21257bddf")

        with AesGcmDecryptContext(key) as ctx:
            plaintext = ctx.decrypt(iv, ciphertext + tag)

        expected = bytes.fromhex("00000000000000000000000000000000")
        assert plaintext == expected


class TestAesGcmRoundTrip:
    """Test encrypt/decrypt round trips."""

    def test_roundtrip_basic(self) -> None:
        """Test basic encrypt/decrypt round trip."""
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        iv = bytes.fromhex("cafebabefacedbaddecaf888")
        original = b"Hello, World! This is a test message."

        with AesGcmEncryptContext(key) as enc_ctx:
            ciphertext = enc_ctx.encrypt(iv, original)

        with AesGcmDecryptContext(key) as dec_ctx:
            decrypted = dec_ctx.decrypt(iv, ciphertext)

        assert decrypted == original

    def test_roundtrip_with_aad(self) -> None:
        """Test round trip with additional authenticated data."""
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        iv = bytes.fromhex("cafebabefacedbaddecaf888")
        aad = b"Associated data that is authenticated but not encrypted"
        original = b"Secret message"

        with AesGcmEncryptContext(key) as enc_ctx:
            ciphertext = enc_ctx.encrypt(iv, original, aad)

        with AesGcmDecryptContext(key) as dec_ctx:
            decrypted = dec_ctx.decrypt(iv, ciphertext, aad)

        assert decrypted == original


class TestAesGcmWycheproof:
    """Test AES-GCM with Wycheproof test vectors."""

    @pytest.mark.parametrize(
        "key,iv,aad,plaintext,ciphertext,tag,expected",
        list(generate_aesgcm_vectors())[:50],  # Limit to first 50 for speed
        ids=lambda x: None,  # Suppress verbose test IDs
    )
    def test_encrypt_wycheproof(
        self,
        key: bytes,
        iv: bytes,
        aad: bytes,
        plaintext: bytes,
        ciphertext: bytes,
        tag: bytes,
        expected: bool | None,
    ) -> None:
        """Test encryption against Wycheproof vectors."""
        if expected is None:
            pytest.skip("Acceptable result - behavior undefined")

        if not expected:
            pytest.skip("Invalid vector - testing valid encryption only")

        with AesGcmEncryptContext(key) as ctx:
            result = ctx.encrypt(iv, plaintext, aad if aad else None)

        expected_output = ciphertext + tag
        assert result == expected_output

    @pytest.mark.parametrize(
        "key,iv,aad,plaintext,ciphertext,tag,expected",
        list(generate_aesgcm_vectors())[:50],  # Limit to first 50 for speed
        ids=lambda x: None,
    )
    def test_decrypt_wycheproof(
        self,
        key: bytes,
        iv: bytes,
        aad: bytes,
        plaintext: bytes,
        ciphertext: bytes,
        tag: bytes,
        expected: bool | None,
    ) -> None:
        """Test decryption against Wycheproof vectors."""
        if expected is None:
            pytest.skip("Acceptable result - behavior undefined")

        with AesGcmDecryptContext(key) as ctx:
            if expected:
                # Valid vector - should decrypt successfully
                result = ctx.decrypt(iv, ciphertext + tag, aad if aad else None)
                assert result == plaintext
            else:
                # Invalid vector - should raise error
                with pytest.raises(Exception):  # CryptoError when implemented
                    ctx.decrypt(iv, ciphertext + tag, aad if aad else None)

