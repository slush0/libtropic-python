"""
Test Pairing Key operations.

Mirrors: libtropic-upstream/tests/functional/lt_test_ire_pairing_key_slots.c

Tests pairing key slot management for secure session establishment.

WARNING: These tests modify pairing key slots which are used for session
authentication. Improper modification can lock you out of the device!
"""

import pytest

from libtropic import PairingKeySlot, Tropic01

from ..conftest import generate_test_data


# Pairing key slot limits
PAIRING_KEY_SLOT_MIN = 0
PAIRING_KEY_SLOT_MAX = 3

# X25519 key length
X25519_KEY_LEN = 32


@pytest.mark.hardware
@pytest.mark.destructive
class TestPairingKeys:
    """
    Tests for pairing key operations.

    Maps to: lt_test_ire_pairing_key_slots()

    WARNING: Be careful with these tests! Modifying pairing keys can
    prevent session establishment if not done correctly.
    """

    def test_read_pairing_key_public(self, device_with_session: Tropic01) -> None:
        """Test reading public portion of pairing key from slot."""
        for slot in range(PAIRING_KEY_SLOT_MIN, PAIRING_KEY_SLOT_MAX + 1):
            public_key = device_with_session.pairing_keys.read(slot)

            # Public key should be 32 bytes (X25519)
            assert len(public_key) == X25519_KEY_LEN, (
                f"Slot {slot}: Expected {X25519_KEY_LEN} bytes, got {len(public_key)}"
            )

    def test_read_pairing_key_enum_slot(self, device_with_session: Tropic01) -> None:
        """Test reading pairing key using enum slot parameter."""
        public_key = device_with_session.pairing_keys.read(PairingKeySlot.SLOT_0)
        assert len(public_key) == X25519_KEY_LEN


@pytest.mark.hardware
@pytest.mark.irreversible
class TestPairingKeysWrite:
    """
    Tests for writing pairing keys.

    WARNING: These tests PERMANENTLY modify pairing key slots!
    Only run on test/development devices where you can recover!

    Writing invalid keys to all slots will lock you out of the device!
    """

    def test_write_pairing_key_warning(self, device_with_session: Tropic01) -> None:
        """
        This test demonstrates pairing key write but DOES NOT execute it
        to prevent accidental lockout.

        To actually test pairing key write:
        1. Ensure you have valid backup keys for at least one slot
        2. Only modify slots you can recover from
        3. Uncomment the write operation
        """
        # Generate a new X25519 public key
        new_public_key = generate_test_data(X25519_KEY_LEN)

        # Read current key from slot 3 (we'll potentially modify this one)
        current_key = device_with_session.pairing_keys.read(PairingKeySlot.SLOT_3)

        # DO NOT UNCOMMENT unless you understand the consequences:
        # Writing an invalid key to a slot makes that slot unusable for session auth!
        # device_with_session.pairing_keys.write(PairingKeySlot.SLOT_3, new_public_key)

        # This test intentionally does nothing to prevent accidents
        assert current_key is not None


@pytest.mark.hardware
@pytest.mark.irreversible
class TestPairingKeysInvalidate:
    """
    Tests for invalidating pairing keys.

    WARNING: Invalidation is PERMANENT! Once a slot is invalidated,
    it can never be used again for session establishment!
    """

    def test_invalidate_pairing_key_warning(self, device_with_session: Tropic01) -> None:
        """
        This test demonstrates pairing key invalidation but DOES NOT execute it
        to prevent permanent damage.

        Invalidation permanently disables a pairing key slot.
        DO NOT invalidate all slots or you'll be locked out!
        """
        # Read current key to verify slot is valid
        current_key = device_with_session.pairing_keys.read(PairingKeySlot.SLOT_3)

        # DO NOT UNCOMMENT unless you understand the consequences:
        # Invalidation is PERMANENT and IRREVERSIBLE!
        # device_with_session.pairing_keys.invalidate(PairingKeySlot.SLOT_3)

        # This test intentionally does nothing to prevent accidents
        assert current_key is not None

