"""
Test ECDSA and EdDSA signing L3 commands.

Mirrors:
    - libtropic-upstream/tests/functional/lt_test_rev_ecdsa_sign.c
    - libtropic-upstream/tests/functional/lt_test_rev_eddsa_sign.c

Tests digital signature operations using P256 (ECDSA) and Ed25519 (EdDSA) keys.
"""

import pytest

from libtropic import EccCurve, InvalidKeyError, Tropic01

from ..conftest import ECC_SLOT_MAX, ECC_SLOT_MIN, generate_test_data

# Signature length (same for both ECDSA and EdDSA)
SIGNATURE_LEN = 64

# EdDSA maximum message length
EDDSA_MSG_LEN_MAX = 4096


@pytest.mark.hardware
@pytest.mark.destructive
class TestEcdsaSign:
    """
    Tests for ECDSA_Sign command.

    Maps to: lt_test_rev_ecdsa_sign()
    """

    def test_ecdsa_sign_all_slots(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """
        Test ECDSA signing with P256 keys on all slots.

        For each slot:
        1. Generate P256 key
        2. Sign random message
        3. Verify signature has correct length
        4. Erase key
        """
        test_message = generate_test_data(256)

        for slot in range(ECC_SLOT_MIN, ECC_SLOT_MAX + 1):
            ecc_slot_cleanup.add(slot)

            # Generate P256 key
            device_with_session.ecc.generate(slot=slot, curve=EccCurve.P256)

            # Sign message
            signature = device_with_session.ecc.sign_ecdsa(slot=slot, message=test_message)

            # Verify signature length
            assert len(signature) == SIGNATURE_LEN, (
                f"Slot {slot}: Expected {SIGNATURE_LEN} bytes, got {len(signature)}"
            )

            # Erase key
            device_with_session.ecc.erase(slot)

    def test_ecdsa_sign_various_message_lengths(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """Test ECDSA signing with various message lengths."""
        slot = 0
        ecc_slot_cleanup.add(slot)

        # Generate key
        device_with_session.ecc.generate(slot=slot, curve=EccCurve.P256)

        # Test various message lengths
        test_lengths = [1, 32, 64, 128, 256, 512, 1024]

        for length in test_lengths:
            message = generate_test_data(length)
            signature = device_with_session.ecc.sign_ecdsa(slot=slot, message=message)
            assert len(signature) == SIGNATURE_LEN

    def test_ecdsa_sign_empty_slot_fails(self, device_with_session: Tropic01) -> None:
        """Test that ECDSA signing with empty slot raises InvalidKeyError."""
        # Slot 0 should be empty (no key)
        message = b"test message"
        with pytest.raises(InvalidKeyError):
            device_with_session.ecc.sign_ecdsa(slot=0, message=message)

    def test_ecdsa_sign_wrong_curve_fails(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """Test that ECDSA signing with Ed25519 key raises InvalidKeyError."""
        slot = 0
        ecc_slot_cleanup.add(slot)

        # Generate Ed25519 key (wrong curve for ECDSA)
        device_with_session.ecc.generate(slot=slot, curve=EccCurve.ED25519)

        # ECDSA sign should fail
        message = b"test message"
        with pytest.raises(InvalidKeyError):
            device_with_session.ecc.sign_ecdsa(slot=slot, message=message)

    def test_ecdsa_signatures_differ(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """
        Test that ECDSA signatures for same message differ (due to random k).

        ECDSA is randomized - each signature should be different even for
        the same message.
        """
        slot = 0
        ecc_slot_cleanup.add(slot)

        device_with_session.ecc.generate(slot=slot, curve=EccCurve.P256)

        message = b"same message"
        signatures = set()

        for _ in range(10):
            signature = device_with_session.ecc.sign_ecdsa(slot=slot, message=message)
            signatures.add(signature)

        # All signatures should be unique
        assert len(signatures) == 10, "ECDSA signatures should be randomized"


@pytest.mark.hardware
@pytest.mark.destructive
class TestEddsaSign:
    """
    Tests for EdDSA_Sign command.

    Maps to: lt_test_rev_eddsa_sign()
    """

    def test_eddsa_sign_all_slots(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """
        Test EdDSA signing with Ed25519 keys on all slots.

        For each slot:
        1. Generate Ed25519 key
        2. Sign random message
        3. Verify signature has correct length
        4. Erase key
        """
        test_message = generate_test_data(256)

        for slot in range(ECC_SLOT_MIN, ECC_SLOT_MAX + 1):
            ecc_slot_cleanup.add(slot)

            # Generate Ed25519 key
            device_with_session.ecc.generate(slot=slot, curve=EccCurve.ED25519)

            # Sign message
            signature = device_with_session.ecc.sign_eddsa(slot=slot, message=test_message)

            # Verify signature length
            assert len(signature) == SIGNATURE_LEN, (
                f"Slot {slot}: Expected {SIGNATURE_LEN} bytes, got {len(signature)}"
            )

            # Erase key
            device_with_session.ecc.erase(slot)

    def test_eddsa_sign_various_message_lengths(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """Test EdDSA signing with various message lengths up to max."""
        slot = 0
        ecc_slot_cleanup.add(slot)

        # Generate key
        device_with_session.ecc.generate(slot=slot, curve=EccCurve.ED25519)

        # Test various message lengths (including max)
        test_lengths = [1, 32, 64, 128, 256, 512, 1024, 2048, EDDSA_MSG_LEN_MAX]

        for length in test_lengths:
            message = generate_test_data(length)
            signature = device_with_session.ecc.sign_eddsa(slot=slot, message=message)
            assert len(signature) == SIGNATURE_LEN

    def test_eddsa_sign_empty_slot_fails(self, device_with_session: Tropic01) -> None:
        """Test that EdDSA signing with empty slot raises InvalidKeyError."""
        message = b"test message"
        with pytest.raises(InvalidKeyError):
            device_with_session.ecc.sign_eddsa(slot=0, message=message)

    def test_eddsa_sign_wrong_curve_fails(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """Test that EdDSA signing with P256 key raises InvalidKeyError."""
        slot = 0
        ecc_slot_cleanup.add(slot)

        # Generate P256 key (wrong curve for EdDSA)
        device_with_session.ecc.generate(slot=slot, curve=EccCurve.P256)

        # EdDSA sign should fail
        message = b"test message"
        with pytest.raises(InvalidKeyError):
            device_with_session.ecc.sign_eddsa(slot=slot, message=message)

    def test_eddsa_signatures_deterministic(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """
        Test that EdDSA signatures for same message are identical.

        Unlike ECDSA, EdDSA is deterministic - same message should produce
        same signature with same key.
        """
        slot = 0
        ecc_slot_cleanup.add(slot)

        device_with_session.ecc.generate(slot=slot, curve=EccCurve.ED25519)

        message = b"same message"
        signatures = []

        for _ in range(5):
            signature = device_with_session.ecc.sign_eddsa(slot=slot, message=message)
            signatures.append(signature)

        # All signatures should be identical
        assert all(s == signatures[0] for s in signatures), (
            "EdDSA signatures should be deterministic"
        )

