"""
Unit tests for secure memory zeroing.

Tests the _cal.memzero module.
"""

import pytest

from libtropic._cal import secure_memzero


class TestSecureMemzero:
    """Tests for secure_memzero() function."""

    def test_zeros_bytearray(self) -> None:
        """Test that bytearray is zeroed."""
        data = bytearray(b"sensitive data here!")
        original_len = len(data)

        secure_memzero(data)

        # Should be all zeros
        assert data == bytearray(original_len)
        assert all(b == 0 for b in data)

    def test_empty_bytearray(self) -> None:
        """Test zeroing empty bytearray."""
        data = bytearray()
        secure_memzero(data)
        assert len(data) == 0

    def test_single_byte(self) -> None:
        """Test zeroing single byte."""
        data = bytearray([0xFF])
        secure_memzero(data)
        assert data == bytearray([0])

    def test_large_buffer(self) -> None:
        """Test zeroing large buffer."""
        data = bytearray(b"\xFF" * 10000)
        secure_memzero(data)
        assert data == bytearray(10000)

    def test_preserves_length(self) -> None:
        """Test that length is preserved."""
        sizes = [0, 1, 16, 32, 100, 1000]
        for size in sizes:
            data = bytearray(size)
            secure_memzero(data)
            assert len(data) == size

    def test_rejects_bytes(self) -> None:
        """Test that immutable bytes is rejected."""
        data = b"cannot be modified"
        with pytest.raises(TypeError):
            secure_memzero(data)  # type: ignore[arg-type]

    def test_rejects_string(self) -> None:
        """Test that string is rejected."""
        data = "cannot be modified"
        with pytest.raises(TypeError):
            secure_memzero(data)  # type: ignore[arg-type]

    def test_rejects_list(self) -> None:
        """Test that list is rejected."""
        data = [1, 2, 3, 4, 5]
        with pytest.raises(TypeError):
            secure_memzero(data)  # type: ignore[arg-type]


class TestSecureMemzeroUseCases:
    """Test secure_memzero in realistic use cases."""

    def test_clear_key_material(self) -> None:
        """Test clearing key material after use."""
        # Simulate key usage
        key = bytearray(b"super_secret_key_12345678901234")
        assert len(key) == 32

        # Use key for something...
        _ = bytes(key)  # Copy for use

        # Clear when done
        secure_memzero(key)
        assert key == bytearray(32)

    def test_clear_password(self) -> None:
        """Test clearing password after authentication."""
        password = bytearray(b"MySecretPassword123!")
        original_len = len(password)

        # Simulate password verification
        _ = password.decode()

        # Clear after use
        secure_memzero(password)
        assert password == bytearray(original_len)

    def test_clear_intermediate_data(self) -> None:
        """Test clearing intermediate cryptographic data."""
        # Simulate intermediate computation
        intermediate = bytearray(64)
        for i in range(64):
            intermediate[i] = i ^ 0xAA

        # Clear after use
        secure_memzero(intermediate)
        assert all(b == 0 for b in intermediate)

