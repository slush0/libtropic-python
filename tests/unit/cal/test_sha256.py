"""
Unit tests for SHA-256 hashing.

Tests the _cal.sha256 module using NIST test vectors.
"""

import pytest

from libtropic._cal import SHA256_DIGEST_LENGTH, Sha256Context, sha256


class TestSha256Function:
    """Tests for one-shot sha256() function."""

    def test_empty_input(self) -> None:
        """Test hash of empty input."""
        result = sha256(b"")
        expected = bytes.fromhex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert result == expected

    def test_abc(self) -> None:
        """Test hash of 'abc' - standard NIST vector."""
        result = sha256(b"abc")
        expected = bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        assert result == expected

    def test_longer_message(self) -> None:
        """Test hash of longer NIST test message."""
        msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        result = sha256(msg)
        expected = bytes.fromhex(
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        )
        assert result == expected

    def test_single_byte(self) -> None:
        """Test hash of single byte."""
        result = sha256(b"\x19")
        expected = bytes.fromhex(
            "68aa2e2ee5dff96e3355e6c7ee373e3d6a4e17f75f9518d843709c0c9bc3e3d4"
        )
        assert result == expected

    def test_output_length(self) -> None:
        """Test that output is always 32 bytes."""
        assert len(sha256(b"")) == SHA256_DIGEST_LENGTH
        assert len(sha256(b"a")) == SHA256_DIGEST_LENGTH
        assert len(sha256(b"a" * 1000)) == SHA256_DIGEST_LENGTH


class TestSha256Context:
    """Tests for incremental Sha256Context."""

    def test_basic_usage(self) -> None:
        """Test basic context usage."""
        ctx = Sha256Context()
        ctx.start()
        ctx.update(b"abc")
        result = ctx.finish()

        expected = bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        assert result == expected

    def test_incremental_update(self) -> None:
        """Test incremental updates produce same result as one-shot."""
        # One-shot
        one_shot = sha256(b"Hello, World!")

        # Incremental
        ctx = Sha256Context()
        ctx.start()
        ctx.update(b"Hello")
        ctx.update(b", ")
        ctx.update(b"World!")
        incremental = ctx.finish()

        assert incremental == one_shot

    def test_empty_update(self) -> None:
        """Test empty update doesn't affect result."""
        ctx = Sha256Context()
        ctx.start()
        ctx.update(b"abc")
        ctx.update(b"")  # Empty update
        result = ctx.finish()

        expected = sha256(b"abc")
        assert result == expected

    def test_context_reuse(self) -> None:
        """Test context can be reused after start()."""
        ctx = Sha256Context()

        # First hash
        ctx.start()
        ctx.update(b"first")
        result1 = ctx.finish()

        # Second hash with same context
        ctx.start()
        ctx.update(b"second")
        result2 = ctx.finish()

        assert result1 == sha256(b"first")
        assert result2 == sha256(b"second")
        assert result1 != result2

    def test_multiple_small_updates(self) -> None:
        """Test many small updates."""
        data = b"a" * 100

        # One-shot
        expected = sha256(data)

        # Many small updates
        ctx = Sha256Context()
        ctx.start()
        for byte in data:
            ctx.update(bytes([byte]))
        result = ctx.finish()

        assert result == expected


class TestSha256NistVectors:
    """Test SHA-256 with NIST test vectors."""

    @pytest.mark.parametrize(
        "input_data,expected_hex",
        [
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (b"\x19", "68aa2e2ee5dff96e3355e6c7ee373e3d6a4e17f75f9518d843709c0c9bc3e3d4"),
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ],
    )
    def test_nist_vectors(self, input_data: bytes, expected_hex: str) -> None:
        """Test against NIST standard test vectors."""
        result = sha256(input_data)
        expected = bytes.fromhex(expected_hex)
        assert result == expected

    def test_million_a(self) -> None:
        """Test hash of one million 'a' characters (NIST vector)."""
        # This is a well-known NIST test vector
        data = b"a" * 1_000_000
        result = sha256(data)
        expected = bytes.fromhex(
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        )
        assert result == expected
