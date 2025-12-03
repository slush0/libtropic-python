"""
Functional tests for libtropic Python bindings.

These tests mirror the C functional tests from libtropic-upstream/tests/functional/
and require actual TROPIC01 hardware to run.

Test Categories:
    - test_ping.py: Ping command tests
    - test_random.py: Hardware RNG tests
    - test_ecc_keys.py: ECC key generation/storage/erasure
    - test_signing.py: ECDSA and EdDSA signing
    - test_memory.py: R-Memory data operations
    - test_config.py: R-Config and I-Config operations
    - test_counters.py: Monotonic counter operations
    - test_mac_and_destroy.py: MAC-and-Destroy operations
    - test_device.py: Device info and session management
"""
