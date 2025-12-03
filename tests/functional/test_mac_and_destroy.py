"""
Test MAC-and-Destroy L3 command.

Mirrors: libtropic-upstream/tests/functional/lt_test_rev_mac_and_destroy.c

Tests the MAC-and-Destroy (M&D) protocol for secure PIN verification
with hardware-enforced attempt limits.
"""

import hashlib
import hmac
import secrets

import pytest

from libtropic import MacAndDestroySlot, Tropic01

from ..conftest import (
    MAC_AND_DESTROY_SLOT_MAX,
    MAC_AND_DESTROY_SLOT_MIN,
    generate_random_length,
    generate_test_data,
    xor_bytes,
)

# MAC-and-Destroy data size (input and output)
MAC_AND_DESTROY_DATA_SIZE = 32

# Maximum PIN length for testing
PIN_LEN_MAX = 2048


def kdf(key: bytes, data: bytes) -> bytes:
    """
    Key Derivation Function using HMAC-SHA256.

    This matches the KDF used in the C tests.
    """
    return hmac.new(key, data, hashlib.sha256).digest()


@pytest.mark.hardware
@pytest.mark.destructive
class TestMacAndDestroy:
    """
    Tests for MAC_And_Destroy command.

    Maps to: lt_test_rev_mac_and_destroy()

    This implements the full M&D protocol test from the C tests, including:
    - PIN setup phase (initializing M&D slots)
    - PIN check phase (verifying correct/incorrect PINs)
    - Slot restoration after correct PIN
    """

    def test_mac_and_destroy_basic(self, device_with_session: Tropic01) -> None:
        """
        Basic MAC-and-Destroy test.

        Verifies that M&D operation returns 32-byte result.
        """
        slot = 0
        challenge = generate_test_data(MAC_AND_DESTROY_DATA_SIZE)

        response = device_with_session.mac_and_destroy.execute(slot=slot, data=challenge)

        assert len(response) == MAC_AND_DESTROY_DATA_SIZE, (
            f"Expected {MAC_AND_DESTROY_DATA_SIZE} bytes, got {len(response)}"
        )

    def test_mac_and_destroy_callable_syntax(self, device_with_session: Tropic01) -> None:
        """Test callable syntax: mac_and_destroy(slot, data)."""
        slot = 0
        challenge = generate_test_data(MAC_AND_DESTROY_DATA_SIZE)

        response = device_with_session.mac_and_destroy(slot=slot, data=challenge)

        assert len(response) == MAC_AND_DESTROY_DATA_SIZE

    def test_mac_and_destroy_all_slots(self, device_with_session: Tropic01) -> None:
        """Test M&D operation on all 128 slots."""
        challenge = generate_test_data(MAC_AND_DESTROY_DATA_SIZE)

        for slot in range(MAC_AND_DESTROY_SLOT_MIN, MAC_AND_DESTROY_SLOT_MAX + 1):
            response = device_with_session.mac_and_destroy.execute(slot=slot, data=challenge)
            assert len(response) == MAC_AND_DESTROY_DATA_SIZE, (
                f"Slot {slot}: Expected {MAC_AND_DESTROY_DATA_SIZE} bytes"
            )

    def test_mac_and_destroy_full_protocol(self, device_with_session: Tropic01) -> None:
        """
        Full M&D protocol test matching the C implementation.

        This test implements the complete PIN setup and verification flow:

        Setup Phase:
        1. Generate random secret s
        2. Compute t = KDF(s, "0") for verification
        3. Compute u = KDF(s, "1") for slot restoration
        4. For each slot i in [0, n):
           - Execute M&D with u (prep)
           - Execute M&D with v = KDF(0, PIN) and get w
           - Execute M&D with u (prep)
           - Compute k_i = KDF(w, PIN)
           - Encrypt c_i = s XOR k_i

        Check Phase:
        1. Compute v = KDF(0, PIN)
        2. Execute M&D with v and get w
        3. Compute k_i = KDF(w, PIN)
        4. Decrypt s = c_i XOR k_i
        5. Verify t' = KDF(s, "0") matches t

        Restoration Phase:
        1. Compute u = KDF(s, "1")
        2. Execute M&D with u for each used slot
        """
        # Number of M&D rounds (slots to use)
        n = secrets.randbelow(MAC_AND_DESTROY_SLOT_MAX) + 1
        n = min(n, 16)  # Limit for reasonable test time

        # Zero key for initial KDF
        kdf_key_zeros = bytes(256)

        # Generate random secret s (32 bytes)
        s = generate_test_data(MAC_AND_DESTROY_DATA_SIZE)

        # Generate random PIN
        pin_len = generate_random_length(PIN_LEN_MAX, min_len=1)
        pin = generate_test_data(pin_len)

        # Compute verification tag t = KDF(s, "0")
        t = kdf(s, b"0")

        # Compute restoration key u = KDF(s, "1")
        u = kdf(s, b"1")

        # Compute v = KDF(zeros, PIN)
        v = kdf(kdf_key_zeros, pin)

        # Setup: Initialize n M&D slots
        ciphertexts: list[bytes] = []
        for i in range(n):
            # Prep slot with u
            device_with_session.mac_and_destroy.execute(slot=i, data=u)

            # Execute with v and get w
            w = device_with_session.mac_and_destroy.execute(slot=i, data=v)

            # Prep slot with u again
            device_with_session.mac_and_destroy.execute(slot=i, data=u)

            # Compute k_i = KDF(w, PIN)
            k_i = kdf(w, pin)

            # Encrypt: c_i = s XOR k_i
            c_i = xor_bytes(s, k_i)
            ciphertexts.append(c_i)

        # Check Phase: Verify PIN with first slot
        slot_to_check = 0

        # Execute M&D with v
        w = device_with_session.mac_and_destroy.execute(slot=slot_to_check, data=v)

        # Compute k_i = KDF(w, PIN)
        k_i = kdf(w, pin)

        # Decrypt: s' = c_i XOR k_i
        s_decrypted = xor_bytes(ciphertexts[slot_to_check], k_i)

        # Verify: t' = KDF(s', "0") should match t
        t_check = kdf(s_decrypted, b"0")
        assert t_check == t, "PIN verification failed: tag mismatch"

        # Verify recovered secret matches original
        assert s_decrypted == s, "Recovered secret doesn't match"

        # Restoration Phase: Restore used slots with u
        for i in range(slot_to_check + 1):
            device_with_session.mac_and_destroy.execute(slot=i, data=u)

    def test_mac_and_destroy_wrong_pin(self, device_with_session: Tropic01) -> None:
        """
        Test M&D with wrong PIN produces wrong verification.

        This simulates an incorrect PIN attempt - the protocol should
        fail to verify (tag mismatch) but not raise an exception.
        """
        # Zero key for KDF
        kdf_key_zeros = bytes(256)

        # Generate secret and correct PIN
        s = generate_test_data(MAC_AND_DESTROY_DATA_SIZE)
        correct_pin = b"correct_pin"
        wrong_pin = b"wrong_pin"

        # Compute values for correct PIN
        t = kdf(s, b"0")  # Verification tag
        u = kdf(s, b"1")  # Restoration key
        v_correct = kdf(kdf_key_zeros, correct_pin)

        # Setup slot 0 with correct PIN
        slot = 0
        device_with_session.mac_and_destroy.execute(slot=slot, data=u)
        w = device_with_session.mac_and_destroy.execute(slot=slot, data=v_correct)
        device_with_session.mac_and_destroy.execute(slot=slot, data=u)
        k_correct = kdf(w, correct_pin)
        ciphertext = xor_bytes(s, k_correct)

        # Attempt verification with wrong PIN
        v_wrong = kdf(kdf_key_zeros, wrong_pin)
        w_wrong = device_with_session.mac_and_destroy.execute(slot=slot, data=v_wrong)
        k_wrong = kdf(w_wrong, wrong_pin)
        s_wrong = xor_bytes(ciphertext, k_wrong)
        t_wrong = kdf(s_wrong, b"0")

        # Verification should fail (tags don't match)
        assert t_wrong != t, "Wrong PIN should not produce valid verification"

    def test_mac_and_destroy_enum_slot(self, device_with_session: Tropic01) -> None:
        """Test using MacAndDestroySlot enum for slot parameter."""
        challenge = generate_test_data(MAC_AND_DESTROY_DATA_SIZE)

        response = device_with_session.mac_and_destroy.execute(
            slot=MacAndDestroySlot.SLOT_5,
            data=challenge
        )

        assert len(response) == MAC_AND_DESTROY_DATA_SIZE

    def test_mac_and_destroy_deterministic(self, device_with_session: Tropic01) -> None:
        """
        Test that same input produces same output (deterministic).

        M&D should be deterministic for the same slot and input.
        """
        slot = 0
        challenge = generate_test_data(MAC_AND_DESTROY_DATA_SIZE)

        # Execute multiple times with same input
        responses = []
        for _ in range(3):
            response = device_with_session.mac_and_destroy.execute(slot=slot, data=challenge)
            responses.append(response)

        # All responses should be identical
        assert all(r == responses[0] for r in responses), (
            "M&D should be deterministic for same input"
        )

    def test_mac_and_destroy_different_inputs(self, device_with_session: Tropic01) -> None:
        """Test that different inputs produce different outputs."""
        slot = 0

        challenge1 = generate_test_data(MAC_AND_DESTROY_DATA_SIZE)
        challenge2 = generate_test_data(MAC_AND_DESTROY_DATA_SIZE)

        # Ensure inputs are different
        while challenge1 == challenge2:
            challenge2 = generate_test_data(MAC_AND_DESTROY_DATA_SIZE)

        response1 = device_with_session.mac_and_destroy.execute(slot=slot, data=challenge1)
        response2 = device_with_session.mac_and_destroy.execute(slot=slot, data=challenge2)

        assert response1 != response2, "Different inputs should produce different outputs"

