"""
X25519 Elliptic Curve Diffie-Hellman for libtropic.

Provides X25519 key exchange operations using Curve25519.
Maps to: lt_x25519.h
"""

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

# X25519 key size in bytes
KEY_SIZE = 32


def x25519(private_key: bytes, public_key: bytes) -> bytes:
    """
    Compute X25519 shared secret.

    Performs Elliptic Curve Diffie-Hellman using Curve25519.
    Both parties compute the same shared secret from their
    private key and the other party's public key.

    Args:
        private_key: 32-byte private key (scalar)
        public_key: 32-byte public key (point on curve)

    Returns:
        32-byte shared secret

    Raises:
        ParamError: If key lengths are invalid
        CryptoError: If computation fails (e.g., invalid public key)

    Example:
        # Alice generates keypair
        alice_private = os.urandom(32)
        alice_public = x25519_scalarmult_base(alice_private)

        # Bob generates keypair
        bob_private = os.urandom(32)
        bob_public = x25519_scalarmult_base(bob_private)

        # Both compute same shared secret
        alice_shared = x25519(alice_private, bob_public)
        bob_shared = x25519(bob_private, alice_public)
        assert alice_shared == bob_shared

    Maps to: lt_X25519()
    """
    if len(private_key) != KEY_SIZE:
        raise ValueError(f"Invalid private key length: {len(private_key)}. Must be 32 bytes.")
    if len(public_key) != KEY_SIZE:
        raise ValueError(f"Invalid public key length: {len(public_key)}. Must be 32 bytes.")

    # Load keys from raw bytes
    priv = X25519PrivateKey.from_private_bytes(private_key)
    pub = X25519PublicKey.from_public_bytes(public_key)

    # Compute shared secret via ECDH
    return priv.exchange(pub)


def x25519_scalarmult_base(private_key: bytes) -> bytes:
    """
    Compute X25519 public key from private key.

    Performs scalar multiplication with the Curve25519 base point
    to derive the public key from a private key.

    Args:
        private_key: 32-byte private key (scalar)

    Returns:
        32-byte public key (point on curve)

    Raises:
        ParamError: If private_key length is not 32

    Example:
        private_key = os.urandom(32)
        public_key = x25519_scalarmult_base(private_key)

    Maps to: lt_X25519_scalarmult()
    """
    if len(private_key) != KEY_SIZE:
        raise ValueError(f"Invalid private key length: {len(private_key)}. Must be 32 bytes.")

    # Load private key and derive public key
    priv = X25519PrivateKey.from_private_bytes(private_key)
    pub = priv.public_key()

    # Return raw bytes of public key
    return pub.public_bytes_raw()
