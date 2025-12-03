"""
Default pairing keys for TROPIC01 secure sessions.

Provides the default SH0 key pairs pre-configured in TROPIC01 devices.
These keys are used to establish the initial secure session before
writing custom pairing keys.

Key Sets:
    - Engineering Sample: For TROPIC01-ES (pre-production) chips
    - Production: For production TROPIC01 chips (default for most devices)

Usage:
    from libtropic import Tropic01
    from libtropic.keys import SH0_PRIV_PROD, SH0_PUB_PROD

    with Tropic01("/dev/ttyACM0") as device:
        stpub = device.get_device_public_key()
        device.start_session(
            stpub=stpub,
            slot=0,
            private_key=SH0_PRIV_PROD,
            public_key=SH0_PUB_PROD,
        )

Note:
    After establishing a session with default keys, you should write your
    own pairing keys and invalidate slot 0 for security.

Maps to: sh0priv_eng_sample, sh0pub_eng_sample, sh0priv_prod0, sh0pub_prod0
"""

# =============================================================================
# Engineering Sample Keys (P/N: TROPIC01-ES)
# =============================================================================

SH0_PRIV_ENG_SAMPLE = bytes([
    0xd0, 0x99, 0x92, 0xb1, 0xf1, 0x7a, 0xbc, 0x4d,
    0xb9, 0x37, 0x17, 0x68, 0xa2, 0x7d, 0xa0, 0x5b,
    0x18, 0xfa, 0xb8, 0x56, 0x13, 0xa7, 0x84, 0x2c,
    0xa6, 0x4c, 0x79, 0x10, 0xf2, 0x2e, 0x71, 0x6b,
])
"""X25519 private key for engineering sample TROPIC01-ES chips."""

SH0_PUB_ENG_SAMPLE = bytes([
    0xe7, 0xf7, 0x35, 0xba, 0x19, 0xa3, 0x3f, 0xd6,
    0x73, 0x23, 0xab, 0x37, 0x26, 0x2d, 0xe5, 0x36,
    0x08, 0xca, 0x57, 0x85, 0x76, 0x53, 0x43, 0x52,
    0xe1, 0x8f, 0x64, 0xe6, 0x13, 0xd3, 0x8d, 0x54,
])
"""X25519 public key for engineering sample TROPIC01-ES chips."""


# =============================================================================
# Production Keys (Default for most TROPIC01 chips)
# =============================================================================

SH0_PRIV_PROD = bytes([
    0x28, 0x3f, 0x5a, 0x0f, 0xfc, 0x41, 0xcf, 0x50,
    0x98, 0xa8, 0xe1, 0x7d, 0xb6, 0x37, 0x2c, 0x3c,
    0xaa, 0xd1, 0xee, 0xee, 0xdf, 0x0f, 0x75, 0xbc,
    0x3f, 0xbf, 0xcd, 0x9c, 0xab, 0x3d, 0xe9, 0x72,
])
"""X25519 private key for production TROPIC01 chips (default)."""

SH0_PUB_PROD = bytes([
    0xf9, 0x75, 0xeb, 0x3c, 0x2f, 0xd7, 0x90, 0xc9,
    0x6f, 0x29, 0x4f, 0x15, 0x57, 0xa5, 0x03, 0x17,
    0x80, 0xc9, 0xaa, 0xfa, 0x14, 0x0d, 0xa2, 0x8f,
    0x55, 0xe7, 0x51, 0x57, 0x37, 0xb2, 0x50, 0x2c,
])
"""X25519 public key for production TROPIC01 chips (default)."""


# =============================================================================
# Aliases (for compatibility with C library naming)
# =============================================================================

# C-style naming aliases
sh0priv_eng_sample = SH0_PRIV_ENG_SAMPLE
sh0pub_eng_sample = SH0_PUB_ENG_SAMPLE
sh0priv_prod0 = SH0_PRIV_PROD
sh0pub_prod0 = SH0_PUB_PROD


__all__ = [
    # Pythonic names (preferred)
    "SH0_PRIV_ENG_SAMPLE",
    "SH0_PUB_ENG_SAMPLE",
    "SH0_PRIV_PROD",
    "SH0_PUB_PROD",
    # C-style aliases
    "sh0priv_eng_sample",
    "sh0pub_eng_sample",
    "sh0priv_prod0",
    "sh0pub_prod0",
]
