"""
Unit tests for HMAC-SHA256 message authentication.

Tests the _cal.hmac_sha256 module using Wycheproof test vectors.
"""

import pytest

from libtropic._cal import HMAC_SHA256_HASH_LENGTH, hmac_sha256

from .conftest import generate_hmac_sha256_vectors


class TestHmacSha256:
    """Tests for hmac_sha256() function."""

    def test_empty_message(self) -> None:
        """Test HMAC of empty message."""
        key = bytes.fromhex(
            "1e225cafb90339bba1b24076d4206c3e79c355805d851682bc818baa4f5a7779"
        )
        result = hmac_sha256(key, b"")
        expected = bytes.fromhex(
            "b175b57d89ea6cb606fb3363f2538abd73a4c00b4a1386905bac809004cf1933"
        )
        assert result == expected

    def test_short_message(self) -> None:
        """Test HMAC of short message."""
        key = bytes.fromhex(
            "8159fd15133cd964c9a6964c94f0ea269a806fd9f43f0da58b6cd1b33d189b2a"
        )
        msg = bytes.fromhex("77")
        result = hmac_sha256(key, msg)
        expected = bytes.fromhex(
            "dfc5105d5eecf7ae7b8b8de3930e7659e84c4172f2555142f1e568fc1872ad93"
        )
        assert result == expected

    def test_output_length(self) -> None:
        """Test that output is always 32 bytes."""
        key = b"secret_key"
        assert len(hmac_sha256(key, b"")) == HMAC_SHA256_HASH_LENGTH
        assert len(hmac_sha256(key, b"short")) == HMAC_SHA256_HASH_LENGTH
        assert len(hmac_sha256(key, b"x" * 1000)) == HMAC_SHA256_HASH_LENGTH

    def test_different_keys_different_output(self) -> None:
        """Test that different keys produce different MACs."""
        msg = b"test message"
        result1 = hmac_sha256(b"key1", msg)
        result2 = hmac_sha256(b"key2", msg)
        assert result1 != result2

    def test_different_messages_different_output(self) -> None:
        """Test that different messages produce different MACs."""
        key = b"secret_key"
        result1 = hmac_sha256(key, b"message1")
        result2 = hmac_sha256(key, b"message2")
        assert result1 != result2

    def test_deterministic(self) -> None:
        """Test that same inputs produce same output."""
        key = b"secret_key"
        msg = b"test message"
        result1 = hmac_sha256(key, msg)
        result2 = hmac_sha256(key, msg)
        assert result1 == result2


class TestHmacSha256Rfc4231:
    """Test HMAC-SHA256 with RFC 4231 test vectors."""

    def test_rfc4231_case1(self) -> None:
        """RFC 4231 Test Case 1."""
        key = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        data = b"Hi There"
        expected = bytes.fromhex(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        )
        assert hmac_sha256(key, data) == expected

    def test_rfc4231_case2(self) -> None:
        """RFC 4231 Test Case 2 - 'Jefe' key."""
        key = b"Jefe"
        data = b"what do ya want for nothing?"
        expected = bytes.fromhex(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        )
        assert hmac_sha256(key, data) == expected

    def test_rfc4231_case3(self) -> None:
        """RFC 4231 Test Case 3."""
        key = bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        data = bytes.fromhex("dd" * 50)
        expected = bytes.fromhex(
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        )
        assert hmac_sha256(key, data) == expected


class TestHmacSha256Wycheproof:
    """Test HMAC-SHA256 with Wycheproof test vectors."""

    @pytest.mark.parametrize(
        "key,msg,expected_tag,expected_result",
        list(generate_hmac_sha256_vectors())[:50],  # Limit for speed
        ids=lambda x: None,
    )
    def test_wycheproof_vectors(
        self,
        key: bytes,
        msg: bytes,
        expected_tag: bytes,
        expected_result: bool | None,
    ) -> None:
        """Test against Wycheproof test vectors."""
        if expected_result is None:
            pytest.skip("Acceptable result - behavior undefined")

        result = hmac_sha256(key, msg)

        if expected_result:
            assert result == expected_tag
        else:
            # Invalid vectors - result should NOT match
            assert result != expected_tag
