"""
Pytest configuration and fixtures for libtropic functional tests.

These fixtures provide common setup for tests that mirror the C functional tests
from libtropic-upstream/tests/functional/.

Test Requirements:
    - Tests require actual TROPIC01 hardware connected via USB dongle
    - Tests marked with @pytest.mark.destructive modify device state
    - Tests marked with @pytest.mark.irreversible permanently modify device
    - Run destructive tests with: pytest -m destructive
    - Skip destructive tests with: pytest -m "not destructive"

Environment Variables:
    - LIBTROPIC_DEVICE: Device path (default: /dev/ttyACM0)
    - LIBTROPIC_RUN_DESTRUCTIVE: Set to "1" to run destructive tests
    - LIBTROPIC_RUN_IRREVERSIBLE: Set to "1" to run irreversible tests
"""

import os
import secrets
from typing import Generator

import pytest

from libtropic import (
    EccCurve,
    EccSlot,
    InvalidKeyError,
    MacAndDestroySlot,
    PairingKeySlot,
    SlotEmptyError,
    Tropic01,
)


# =============================================================================
# Test Configuration
# =============================================================================

# Default test device path
DEFAULT_DEVICE = "/dev/ttyACM0"

# Test pairing keys (SH0) - from libtropic C tests
# WARNING: These are DEFAULT TEST KEYS - never use in production!
TEST_SH0_PRIV = bytes.fromhex(
    "d4bb385d67f28e4ab6e308ee92dd5c69"
    "19ff42b5ae9a40d2e21bd1e8c7a0e69f"
)
TEST_SH0_PUB = bytes.fromhex(
    "92b8afd0f31b75c29a9b6f1f1e9b9f8e"
    "7c6d5a4b3c2d1e0f1a2b3c4d5e6f7a8b"
)

# Limits from TROPIC01 specification
ECC_SLOT_MIN = 0
ECC_SLOT_MAX = 31
R_MEM_DATA_SLOT_MIN = 0
R_MEM_DATA_SLOT_MAX = 511
MCOUNTER_MIN = 0
MCOUNTER_MAX = 15
MAC_AND_DESTROY_SLOT_MIN = 0
MAC_AND_DESTROY_SLOT_MAX = 127
PING_LEN_MAX = 4096
R_MEM_DATA_SIZE_MAX = 475  # Maximum data size per slot

# HMAC-SHA256 hash length
HMAC_LEN = 32


# =============================================================================
# Pytest Markers
# =============================================================================

def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "destructive: Tests that modify device state (slots, keys, etc.)"
    )
    config.addinivalue_line(
        "markers", "irreversible: Tests that permanently modify device (I-Config, pairing keys)"
    )
    config.addinivalue_line(
        "markers", "hardware: Tests that require actual TROPIC01 hardware"
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip destructive/irreversible tests unless explicitly enabled."""
    run_destructive = os.environ.get("LIBTROPIC_RUN_DESTRUCTIVE", "0") == "1"
    run_irreversible = os.environ.get("LIBTROPIC_RUN_IRREVERSIBLE", "0") == "1"

    skip_destructive = pytest.mark.skip(
        reason="Destructive test - set LIBTROPIC_RUN_DESTRUCTIVE=1 to run"
    )
    skip_irreversible = pytest.mark.skip(
        reason="Irreversible test - set LIBTROPIC_RUN_IRREVERSIBLE=1 to run"
    )

    for item in items:
        if "destructive" in item.keywords and not run_destructive:
            item.add_marker(skip_destructive)
        if "irreversible" in item.keywords and not run_irreversible:
            item.add_marker(skip_irreversible)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def device_path() -> str:
    """Get device path from environment or use default."""
    return os.environ.get("LIBTROPIC_DEVICE", DEFAULT_DEVICE)


@pytest.fixture
def device(device_path: str) -> Generator[Tropic01, None, None]:
    """
    Provide initialized Tropic01 device (no session).

    Use for tests that only need device-level operations.
    """
    dev = Tropic01(device_path)
    dev.open()
    try:
        yield dev
    finally:
        dev.close()


@pytest.fixture
def device_with_session(device_path: str) -> Generator[Tropic01, None, None]:
    """
    Provide Tropic01 device with active secure session using SH0 keys.

    Use for tests that require L3 (session-protected) operations.
    """
    dev = Tropic01(device_path)
    dev.open()
    dev.start_session(
        private_key=TEST_SH0_PRIV,
        public_key=TEST_SH0_PUB,
        slot=PairingKeySlot.SLOT_0
    )
    try:
        yield dev
    finally:
        # Always abort session before closing
        if dev.has_session:
            dev.abort_session()
        dev.close()


@pytest.fixture
def random_bytes_factory(device_with_session: Tropic01):
    """
    Factory fixture for generating random bytes from hardware RNG.

    Returns a callable that generates random bytes using the device RNG.
    Falls back to Python's secrets module if device call fails.
    """
    def generate(length: int) -> bytes:
        try:
            return device_with_session.random.get_bytes(length)
        except NotImplementedError:
            # Stub not implemented yet - use Python RNG for test setup
            return secrets.token_bytes(length)
    return generate


# =============================================================================
# Cleanup Fixtures
# =============================================================================

@pytest.fixture
def ecc_slot_cleanup(device_with_session: Tropic01):
    """
    Fixture that tracks used ECC slots and cleans them up after test.

    Usage:
        def test_something(device_with_session, ecc_slot_cleanup):
            ecc_slot_cleanup.add(slot=0)
            device_with_session.ecc.generate(slot=0, curve=EccCurve.P256)
            # Slot 0 will be erased after test
    """
    class SlotTracker:
        def __init__(self, device: Tropic01):
            self.device = device
            self.slots: set[int] = set()

        def add(self, slot: int) -> None:
            self.slots.add(slot)

        def cleanup(self) -> None:
            for slot in self.slots:
                try:
                    self.device.ecc.erase(slot)
                except (InvalidKeyError, NotImplementedError):
                    pass  # Slot already empty or not implemented

    tracker = SlotTracker(device_with_session)
    yield tracker
    tracker.cleanup()


@pytest.fixture
def r_mem_slot_cleanup(device_with_session: Tropic01):
    """
    Fixture that tracks used R-Memory slots and cleans them up after test.

    Usage:
        def test_something(device_with_session, r_mem_slot_cleanup):
            r_mem_slot_cleanup.add(slot=100)
            device_with_session.memory.write(slot=100, data=b"test")
            # Slot 100 will be erased after test
    """
    class SlotTracker:
        def __init__(self, device: Tropic01):
            self.device = device
            self.slots: set[int] = set()

        def add(self, slot: int) -> None:
            self.slots.add(slot)

        def cleanup(self) -> None:
            for slot in self.slots:
                try:
                    self.device.memory.erase(slot)
                except (SlotEmptyError, NotImplementedError):
                    pass  # Slot already empty or not implemented

    tracker = SlotTracker(device_with_session)
    yield tracker
    tracker.cleanup()


# =============================================================================
# Helper Functions (for use in tests)
# =============================================================================

def generate_random_length(max_len: int, min_len: int = 1) -> int:
    """Generate random length between min_len and max_len (inclusive)."""
    return secrets.randbelow(max_len - min_len + 1) + min_len


def generate_test_data(length: int) -> bytes:
    """Generate random test data of specified length."""
    return secrets.token_bytes(length)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte arrays of equal length."""
    if len(a) != len(b):
        raise ValueError("Byte arrays must have equal length")
    return bytes(x ^ y for x, y in zip(a, b))
