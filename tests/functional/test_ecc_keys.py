"""
Test ECC Key Generate, Store, Read, and Erase L3 commands.

Mirrors:
    - libtropic-upstream/tests/functional/lt_test_rev_ecc_key_generate.c
    - libtropic-upstream/tests/functional/lt_test_rev_ecc_key_store.c

Tests ECC key operations on all 32 slots (0-31) for both P256 and Ed25519 curves.
"""

import pytest

from libtropic import (
    EccCurve,
    EccKeyOrigin,
    InvalidKeyError,
    SlotNotEmptyError,
    Tropic01,
)
from libtropic.types import EccKeyInfo

from ..conftest import ECC_SLOT_MAX, ECC_SLOT_MIN, generate_test_data


# Key sizes
P256_PUBKEY_LEN = 64  # Uncompressed P256 public key
ED25519_PUBKEY_LEN = 32  # Ed25519 public key
PRIVKEY_LEN = 32  # Private key length for both curves


@pytest.mark.hardware
@pytest.mark.destructive
class TestEccKeyGenerate:
    """
    Tests for ECC_Key_Generate, ECC_Key_Read, and ECC_Key_Erase commands.

    Maps to: lt_test_rev_ecc_key_generate()
    """

    def test_generate_p256_all_slots(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """
        Test ECC key generation using P256 curve on all slots.

        For each slot:
        1. Verify slot is empty
        2. Generate P256 key
        3. Verify generate again fails (slot not empty)
        4. Verify generate Ed25519 fails (slot not empty)
        5. Read and verify key info
        6. Erase slot
        """
        for slot in range(ECC_SLOT_MIN, ECC_SLOT_MAX + 1):
            ecc_slot_cleanup.add(slot)

            # Verify slot is empty (read should fail)
            with pytest.raises(InvalidKeyError):
                device_with_session.ecc.read(slot)

            # Generate P256 key
            device_with_session.ecc.generate(slot=slot, curve=EccCurve.P256)

            # Generate again should fail (slot not empty)
            with pytest.raises(SlotNotEmptyError):
                device_with_session.ecc.generate(slot=slot, curve=EccCurve.P256)

            # Generate with different curve should also fail
            with pytest.raises(SlotNotEmptyError):
                device_with_session.ecc.generate(slot=slot, curve=EccCurve.ED25519)

            # Read and verify key info
            key_info: EccKeyInfo = device_with_session.ecc.read(slot)
            assert key_info.curve == EccCurve.P256
            assert key_info.origin == EccKeyOrigin.GENERATED
            assert len(key_info.public_key) == P256_PUBKEY_LEN

            # Erase slot
            device_with_session.ecc.erase(slot)

    def test_generate_ed25519_all_slots(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """
        Test ECC key generation using Ed25519 curve on all slots.

        For each slot:
        1. Verify slot is empty
        2. Generate Ed25519 key
        3. Verify generate again fails (slot not empty)
        4. Verify generate P256 fails (slot not empty)
        5. Read and verify key info
        6. Erase and verify slot is empty
        """
        for slot in range(ECC_SLOT_MIN, ECC_SLOT_MAX + 1):
            ecc_slot_cleanup.add(slot)

            # Verify slot is empty
            with pytest.raises(InvalidKeyError):
                device_with_session.ecc.read(slot)

            # Generate Ed25519 key
            device_with_session.ecc.generate(slot=slot, curve=EccCurve.ED25519)

            # Generate again should fail
            with pytest.raises(SlotNotEmptyError):
                device_with_session.ecc.generate(slot=slot, curve=EccCurve.ED25519)

            # Generate with different curve should also fail
            with pytest.raises(SlotNotEmptyError):
                device_with_session.ecc.generate(slot=slot, curve=EccCurve.P256)

            # Read and verify key info
            key_info: EccKeyInfo = device_with_session.ecc.read(slot)
            assert key_info.curve == EccCurve.ED25519
            assert key_info.origin == EccKeyOrigin.GENERATED
            assert len(key_info.public_key) == ED25519_PUBKEY_LEN

            # Erase slot
            device_with_session.ecc.erase(slot)

            # Verify slot is empty after erase
            with pytest.raises(InvalidKeyError):
                device_with_session.ecc.read(slot)


@pytest.mark.hardware
@pytest.mark.destructive
class TestEccKeyStore:
    """
    Tests for ECC_Key_Store command.

    Maps to: lt_test_rev_ecc_key_store()
    """

    def test_store_p256_all_slots(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """
        Test storing P256 private keys on all slots.

        For each slot:
        1. Generate random private key
        2. Store the key
        3. Read and verify key info (origin = STORED)
        4. Erase slot
        """
        for slot in range(ECC_SLOT_MIN, ECC_SLOT_MAX + 1):
            ecc_slot_cleanup.add(slot)

            # Generate random private key
            private_key = generate_test_data(PRIVKEY_LEN)

            # Store the key
            device_with_session.ecc.store(
                slot=slot,
                curve=EccCurve.P256,
                private_key=private_key
            )

            # Read and verify key info
            key_info: EccKeyInfo = device_with_session.ecc.read(slot)
            assert key_info.curve == EccCurve.P256
            assert key_info.origin == EccKeyOrigin.STORED
            assert len(key_info.public_key) == P256_PUBKEY_LEN

            # Store again should fail (slot not empty)
            another_key = generate_test_data(PRIVKEY_LEN)
            with pytest.raises(SlotNotEmptyError):
                device_with_session.ecc.store(
                    slot=slot,
                    curve=EccCurve.P256,
                    private_key=another_key
                )

            # Erase slot
            device_with_session.ecc.erase(slot)

    def test_store_ed25519_all_slots(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """
        Test storing Ed25519 private keys on all slots.

        For each slot:
        1. Generate random private key
        2. Store the key
        3. Read and verify key info (origin = STORED)
        4. Erase slot
        """
        for slot in range(ECC_SLOT_MIN, ECC_SLOT_MAX + 1):
            ecc_slot_cleanup.add(slot)

            # Generate random private key
            private_key = generate_test_data(PRIVKEY_LEN)

            # Store the key
            device_with_session.ecc.store(
                slot=slot,
                curve=EccCurve.ED25519,
                private_key=private_key
            )

            # Read and verify key info
            key_info: EccKeyInfo = device_with_session.ecc.read(slot)
            assert key_info.curve == EccCurve.ED25519
            assert key_info.origin == EccKeyOrigin.STORED
            assert len(key_info.public_key) == ED25519_PUBKEY_LEN

            # Erase slot
            device_with_session.ecc.erase(slot)

    def test_store_then_generate_fails(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """Test that generate fails on slot with stored key."""
        slot = 0
        ecc_slot_cleanup.add(slot)

        # Store a key
        private_key = generate_test_data(PRIVKEY_LEN)
        device_with_session.ecc.store(
            slot=slot,
            curve=EccCurve.P256,
            private_key=private_key
        )

        # Generate should fail
        with pytest.raises(SlotNotEmptyError):
            device_with_session.ecc.generate(slot=slot, curve=EccCurve.P256)

    def test_generate_then_store_fails(
        self,
        device_with_session: Tropic01,
        ecc_slot_cleanup,
    ) -> None:
        """Test that store fails on slot with generated key."""
        slot = 0
        ecc_slot_cleanup.add(slot)

        # Generate a key
        device_with_session.ecc.generate(slot=slot, curve=EccCurve.ED25519)

        # Store should fail
        private_key = generate_test_data(PRIVKEY_LEN)
        with pytest.raises(SlotNotEmptyError):
            device_with_session.ecc.store(
                slot=slot,
                curve=EccCurve.ED25519,
                private_key=private_key
            )

