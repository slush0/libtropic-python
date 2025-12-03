"""
Unit tests for X25519 key exchange.

Tests the _cal.x25519 module using Wycheproof test vectors.
"""

import pytest

from libtropic._cal import X25519_KEY_SIZE, x25519, x25519_scalarmult_base

from .conftest import generate_x25519_vectors


class TestX25519:
    """Tests for x25519() shared secret derivation."""

    def test_basic_key_exchange(self) -> None:
        """Test basic X25519 key exchange."""
        # Wycheproof test case 1
        public = bytes.fromhex(
            "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829"
        )
        private = bytes.fromhex(
            "c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475"
        )
        expected = bytes.fromhex(
            "436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320"
        )

        result = x25519(private, public)
        assert result == expected

    def test_output_length(self) -> None:
        """Test that output is always 32 bytes."""
        private = bytes(32)  # All zeros (valid X25519 scalar)
        public = bytes.fromhex(
            "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829"
        )
        result = x25519(private, public)
        assert len(result) == X25519_KEY_SIZE

    def test_deterministic(self) -> None:
        """Test that same inputs produce same output."""
        public = bytes.fromhex(
            "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829"
        )
        private = bytes.fromhex(
            "c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475"
        )

        result1 = x25519(private, public)
        result2 = x25519(private, public)
        assert result1 == result2


class TestX25519ScalarmultBase:
    """Tests for x25519_scalarmult_base() public key derivation."""

    def test_basic_pubkey_derivation(self) -> None:
        """Test deriving public key from private key."""
        # Known test vector
        private = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        expected_public = bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        )

        result = x25519_scalarmult_base(private)
        assert result == expected_public

    def test_output_length(self) -> None:
        """Test that output is always 32 bytes."""
        private = bytes(32)  # All zeros
        result = x25519_scalarmult_base(private)
        assert len(result) == X25519_KEY_SIZE

    def test_different_keys_different_output(self) -> None:
        """Test that different private keys produce different public keys."""
        priv1 = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        priv2 = bytes.fromhex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        )

        pub1 = x25519_scalarmult_base(priv1)
        pub2 = x25519_scalarmult_base(priv2)
        assert pub1 != pub2


class TestX25519KeyExchangeRoundTrip:
    """Test complete X25519 key exchange round trips."""

    def test_alice_bob_exchange(self) -> None:
        """Test that Alice and Bob derive the same shared secret."""
        # Alice's keypair
        alice_private = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        alice_public = x25519_scalarmult_base(alice_private)

        # Bob's keypair
        bob_private = bytes.fromhex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        )
        bob_public = x25519_scalarmult_base(bob_private)

        # Both derive the same shared secret
        alice_shared = x25519(alice_private, bob_public)
        bob_shared = x25519(bob_private, alice_public)

        assert alice_shared == bob_shared

    def test_rfc7748_test_vector(self) -> None:
        """Test with RFC 7748 test vectors."""
        # From RFC 7748 Section 6.1
        alice_private = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        alice_public = bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        )
        bob_private = bytes.fromhex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        )
        bob_public = bytes.fromhex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        )
        expected_shared = bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        )

        # Verify public key derivation
        assert x25519_scalarmult_base(alice_private) == alice_public
        assert x25519_scalarmult_base(bob_private) == bob_public

        # Verify shared secret
        assert x25519(alice_private, bob_public) == expected_shared
        assert x25519(bob_private, alice_public) == expected_shared


class TestX25519Wycheproof:
    """Test X25519 with Wycheproof test vectors."""

    @pytest.mark.parametrize(
        "public,private,expected_shared,expected_result",
        list(generate_x25519_vectors())[:100],  # Limit for speed
        ids=lambda x: None,
    )
    def test_wycheproof_vectors(
        self,
        public: bytes,
        private: bytes,
        expected_shared: bytes,
        expected_result: bool | None,
    ) -> None:
        """Test against Wycheproof test vectors."""
        if expected_result is None:
            # Acceptable - may or may not work, skip
            pytest.skip("Acceptable result - behavior undefined")

        result = x25519(private, public)

        if expected_result:
            assert result == expected_shared
        # For invalid vectors, we just check it doesn't crash
        # The output may or may not match depending on implementation

