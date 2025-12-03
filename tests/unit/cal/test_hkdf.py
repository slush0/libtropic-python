"""
Unit tests for HKDF key derivation.

Tests the _cal.hkdf module.

Note: libtropic uses a simplified HKDF variant specific to the TROPIC01 protocol,
which always produces two 32-byte outputs. This is NOT the full RFC 5869 HKDF.
"""


from libtropic._cal import HKDF_OUTPUT_LENGTH, hkdf


class TestHkdf:
    """Tests for hkdf() function."""

    def test_basic_derivation(self) -> None:
        """Test basic key derivation."""
        chaining_key = bytes(32)  # 32 zero bytes
        input_data = b"input keying material"

        output1, output2 = hkdf(chaining_key, input_data)

        # Both outputs should be 32 bytes
        assert len(output1) == HKDF_OUTPUT_LENGTH
        assert len(output2) == HKDF_OUTPUT_LENGTH

        # Outputs should be different
        assert output1 != output2

    def test_deterministic(self) -> None:
        """Test that same inputs produce same outputs."""
        ck = bytes.fromhex("0" * 64)
        ikm = b"test input"

        out1a, out2a = hkdf(ck, ikm)
        out1b, out2b = hkdf(ck, ikm)

        assert out1a == out1b
        assert out2a == out2b

    def test_different_chaining_keys(self) -> None:
        """Test that different chaining keys produce different outputs."""
        ikm = b"same input"

        ck1 = bytes(32)
        ck2 = bytes([1] + [0] * 31)

        out1a, out2a = hkdf(ck1, ikm)
        out1b, out2b = hkdf(ck2, ikm)

        assert out1a != out1b
        assert out2a != out2b

    def test_different_inputs(self) -> None:
        """Test that different inputs produce different outputs."""
        ck = bytes(32)

        out1a, out2a = hkdf(ck, b"input1")
        out1b, out2b = hkdf(ck, b"input2")

        assert out1a != out1b
        assert out2a != out2b

    def test_empty_input(self) -> None:
        """Test with empty input data."""
        ck = bytes(32)

        output1, output2 = hkdf(ck, b"")

        assert len(output1) == HKDF_OUTPUT_LENGTH
        assert len(output2) == HKDF_OUTPUT_LENGTH

    def test_long_input(self) -> None:
        """Test with long input data."""
        ck = bytes(32)
        long_input = b"x" * 10000

        output1, output2 = hkdf(ck, long_input)

        assert len(output1) == HKDF_OUTPUT_LENGTH
        assert len(output2) == HKDF_OUTPUT_LENGTH


class TestHkdfLibtropicProtocol:
    """
    Test HKDF as used in libtropic protocol.

    The libtropic HKDF is defined as:
        tmp = HMAC-SHA256(chaining_key, input_data)
        output_1 = HMAC-SHA256(tmp, 0x01)
        output_2 = HMAC-SHA256(tmp, output_1 || 0x02)
    """

    def test_matches_manual_computation(self) -> None:
        """Test that hkdf() matches manual HMAC-based computation."""
        from libtropic._cal import hmac_sha256

        ck = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        )
        ikm = b"test input keying material"

        # Manual computation per libtropic spec
        tmp = hmac_sha256(ck, ikm)
        expected_out1 = hmac_sha256(tmp, bytes([0x01]))
        expected_out2 = hmac_sha256(tmp, expected_out1 + bytes([0x02]))

        # Compare with hkdf()
        out1, out2 = hkdf(ck, ikm)

        assert out1 == expected_out1
        assert out2 == expected_out2

    def test_chaining(self) -> None:
        """Test key chaining as used in session establishment."""
        # Initial chaining key
        ck0 = bytes(32)
        shared_secret = bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        )

        # First derivation
        ck1, k1 = hkdf(ck0, shared_secret)

        # Chain to next derivation
        ck2, k2 = hkdf(ck1, b"some transcript data")

        # All outputs should be unique
        assert len({ck0.hex(), ck1.hex(), ck2.hex(), k1.hex(), k2.hex()}) == 5

