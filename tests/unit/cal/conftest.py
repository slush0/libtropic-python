"""
Shared fixtures and utilities for CAL unit tests.

Provides Wycheproof test vector loading and common test utilities.
"""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

# Path to Wycheproof test vectors
WYCHEPROOF_DIR = Path(__file__).parent.parent.parent / "wycheproof"


def load_wycheproof_vectors(filename: str) -> dict[str, Any]:
    """Load Wycheproof test vectors from JSON file."""
    filepath = WYCHEPROOF_DIR / filename
    with open(filepath) as f:
        return json.load(f)


def parse_wycheproof_result(result: str) -> bool | None:
    """
    Parse Wycheproof result string.

    Returns:
        True for "valid", False for "invalid", None for "acceptable"
    """
    if result == "valid":
        return True
    elif result == "invalid":
        return False
    elif result == "acceptable":
        return None
    else:
        raise ValueError(f"Unknown result: {result}")


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_string)


# ============================================================================
# AES-GCM Test Vectors
# ============================================================================

def generate_aesgcm_vectors() -> Iterator[tuple[bytes, bytes, bytes, bytes, bytes, bytes, bool | None]]:
    """
    Generate AES-GCM test vectors from Wycheproof.

    Yields:
        (key, iv, aad, plaintext, ciphertext, tag, expected_result)
    """
    data = load_wycheproof_vectors("aes_gcm_test.json")

    for group in data["testGroups"]:
        # Only use standard tag size (128 bits = 16 bytes)
        if group.get("tagSize", 128) != 128:
            continue
        # Only use standard IV size (96 bits = 12 bytes)
        if group.get("ivSize", 96) != 96:
            continue

        for test in group["tests"]:
            key = hex_to_bytes(test["key"])
            iv = hex_to_bytes(test["iv"])
            aad = hex_to_bytes(test["aad"])
            plaintext = hex_to_bytes(test["msg"])
            ciphertext = hex_to_bytes(test["ct"])
            tag = hex_to_bytes(test["tag"])
            result = parse_wycheproof_result(test["result"])

            yield (key, iv, aad, plaintext, ciphertext, tag, result)


@pytest.fixture
def aesgcm_vectors() -> list[tuple[bytes, bytes, bytes, bytes, bytes, bytes, bool | None]]:
    """Fixture providing AES-GCM test vectors."""
    return list(generate_aesgcm_vectors())


# ============================================================================
# HMAC-SHA256 Test Vectors
# ============================================================================

def generate_hmac_sha256_vectors() -> Iterator[tuple[bytes, bytes, bytes, bool | None]]:
    """
    Generate HMAC-SHA256 test vectors from Wycheproof.

    Yields:
        (key, message, expected_tag, expected_result)
    """
    data = load_wycheproof_vectors("hmac_sha256_test.json")

    for group in data["testGroups"]:
        # Only use full tag size (256 bits = 32 bytes)
        if group.get("tagSize", 256) != 256:
            continue

        for test in group["tests"]:
            key = hex_to_bytes(test["key"])
            msg = hex_to_bytes(test["msg"])
            tag = hex_to_bytes(test["tag"])
            result = parse_wycheproof_result(test["result"])

            yield (key, msg, tag, result)


@pytest.fixture
def hmac_sha256_vectors() -> list[tuple[bytes, bytes, bytes, bool | None]]:
    """Fixture providing HMAC-SHA256 test vectors."""
    return list(generate_hmac_sha256_vectors())


# ============================================================================
# X25519 Test Vectors
# ============================================================================

def generate_x25519_vectors() -> Iterator[tuple[bytes, bytes, bytes, bool | None]]:
    """
    Generate X25519 test vectors from Wycheproof.

    Yields:
        (public_key, private_key, expected_shared, expected_result)
    """
    data = load_wycheproof_vectors("x25519_test.json")

    for group in data["testGroups"]:
        if group.get("curve") != "curve25519":
            continue

        for test in group["tests"]:
            public = hex_to_bytes(test["public"])
            private = hex_to_bytes(test["private"])
            shared = hex_to_bytes(test["shared"])
            result = parse_wycheproof_result(test["result"])

            yield (public, private, shared, result)


@pytest.fixture
def x25519_vectors() -> list[tuple[bytes, bytes, bytes, bool | None]]:
    """Fixture providing X25519 test vectors."""
    return list(generate_x25519_vectors())


# ============================================================================
# HKDF-SHA256 Test Vectors
# ============================================================================

def generate_hkdf_vectors() -> Iterator[tuple[bytes, bytes, bytes, int, bytes, bool | None]]:
    """
    Generate HKDF-SHA256 test vectors from Wycheproof.

    Yields:
        (ikm, salt, info, size, expected_okm, expected_result)
    """
    data = load_wycheproof_vectors("hkdf_sha256_test.json")

    for group in data["testGroups"]:
        for test in group["tests"]:
            ikm = hex_to_bytes(test["ikm"])
            salt = hex_to_bytes(test["salt"])
            info = hex_to_bytes(test["info"])
            size = test["size"]
            okm = hex_to_bytes(test["okm"])
            result = parse_wycheproof_result(test["result"])

            yield (ikm, salt, info, size, okm, result)


@pytest.fixture
def hkdf_vectors() -> list[tuple[bytes, bytes, bytes, int, bytes, bool | None]]:
    """Fixture providing HKDF-SHA256 test vectors."""
    return list(generate_hkdf_vectors())


# ============================================================================
# SHA256 Test Vectors (NIST)
# ============================================================================

# NIST test vectors from trezor_crypto/tests/test_check.c
SHA256_NIST_VECTORS = [
    # (input_bytes, expected_hash_hex)
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
    (b"\x19", "68aa2e2ee5dff96e3355e6c7ee373e3d6a4e17f75f9518d843709c0c9bc3e3d4"),
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
]


@pytest.fixture
def sha256_vectors() -> list[tuple[bytes, str]]:
    """Fixture providing SHA256 NIST test vectors."""
    return SHA256_NIST_VECTORS.copy()

