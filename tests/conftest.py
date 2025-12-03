"""
Pytest configuration and fixtures for libtropic functional tests.

These fixtures provide common setup for tests that mirror the C functional tests
from libtropic-upstream/tests/functional/.

Test Requirements:
    - Tests require actual TROPIC01 hardware connected via USB dongle or SPI
    - Tests marked with @pytest.mark.destructive modify device state
    - Tests marked with @pytest.mark.irreversible permanently modify device
    - Run destructive tests with: pytest -m destructive
    - Skip destructive tests with: pytest -m "not destructive"

Environment Variables:
    Transport selection:
        - LIBTROPIC_TRANSPORT: Transport type ("usb" or "spi", default: "usb")

    USB dongle settings (when LIBTROPIC_TRANSPORT=usb):
        - LIBTROPIC_DEVICE: Device path (default: /dev/ttyACM0)

    SPI settings (when LIBTROPIC_TRANSPORT=spi):
        - LIBTROPIC_SPI_DEVICE: SPI device path (default: /dev/spidev0.0)
        - LIBTROPIC_SPI_SPEED_HZ: SPI clock speed in Hz (default: 1000000)
        - LIBTROPIC_GPIO_CHIP: GPIO chip device (default: /dev/gpiochip0)
        - LIBTROPIC_CS_PIN: GPIO pin for chip select (default: 8)
        - LIBTROPIC_INT_PIN: GPIO pin for interrupt (optional, no default)

    Key configuration:
        - LIBTROPIC_KEY_CONFIG: Key configuration to use:
            - "engineering" (default): Engineering sample keys at slot 0
            - "hwwallet": Hardware wallet example keys at slot 1

    Test control:
        - LIBTROPIC_RUN_DESTRUCTIVE: Set to "1" to run destructive tests
        - LIBTROPIC_RUN_IRREVERSIBLE: Set to "1" to run irreversible tests
"""

import os
import secrets
from collections.abc import Generator
from dataclasses import dataclass

import pytest

from libtropic import (
    InvalidKeyError,
    LinuxSpiTransport,
    PairingKeySlot,
    SlotEmptyError,
    SpiConfig,
    Transport,
    Tropic01,
    UsbDongleConfig,
    UsbDongleTransport,
)

# =============================================================================
# Test Configuration
# =============================================================================

# Transport type: "usb" or "spi"
TRANSPORT_TYPE = os.environ.get("LIBTROPIC_TRANSPORT", "usb").lower()

# USB dongle settings
DEFAULT_USB_DEVICE = "/dev/ttyACM0"

# SPI default settings
DEFAULT_SPI_DEVICE = "/dev/spidev0.0"
DEFAULT_SPI_SPEED_HZ = 1_000_000
DEFAULT_GPIO_CHIP = "/dev/gpiochip0"
DEFAULT_CS_PIN = 8


def create_transport() -> Transport:
    """
    Create transport based on environment configuration.

    Returns:
        Transport instance (USB dongle or Linux SPI) based on LIBTROPIC_TRANSPORT.

    Raises:
        ValueError: If LIBTROPIC_TRANSPORT has invalid value.
    """
    if TRANSPORT_TYPE == "spi":
        # Parse SPI configuration from environment
        spi_device = os.environ.get("LIBTROPIC_SPI_DEVICE", DEFAULT_SPI_DEVICE)
        spi_speed_hz = int(os.environ.get("LIBTROPIC_SPI_SPEED_HZ", DEFAULT_SPI_SPEED_HZ))
        gpio_chip = os.environ.get("LIBTROPIC_GPIO_CHIP", DEFAULT_GPIO_CHIP)
        cs_pin = int(os.environ.get("LIBTROPIC_CS_PIN", DEFAULT_CS_PIN))

        # INT pin is optional
        int_pin_str = os.environ.get("LIBTROPIC_INT_PIN")
        int_pin = int(int_pin_str) if int_pin_str else None

        config = SpiConfig(
            spi_device=spi_device,
            spi_speed_hz=spi_speed_hz,
            gpio_chip=gpio_chip,
            cs_pin=cs_pin,
            int_pin=int_pin,
        )
        return LinuxSpiTransport(config)

    elif TRANSPORT_TYPE == "usb":
        device_path = os.environ.get("LIBTROPIC_DEVICE", DEFAULT_USB_DEVICE)
        config = UsbDongleConfig(device_path=device_path)
        return UsbDongleTransport(config)

    else:
        raise ValueError(
            f"Invalid LIBTROPIC_TRANSPORT='{TRANSPORT_TYPE}'. "
            f"Valid options: 'usb', 'spi'"
        )


@dataclass
class KeyConfig:
    """Configuration for pairing keys used in tests."""
    name: str
    private_key: bytes
    public_key: bytes
    slot: PairingKeySlot


# Engineering sample keys (SH0) - from libtropic_default_sh0_keys.c
# Used on fresh/virgin TROPIC01 devices
KEY_CONFIG_ENGINEERING = KeyConfig(
    name="engineering",
    private_key=bytes.fromhex(
        "d09992b1f17abc4db9371768a27da05b"
        "18fab85613a7842ca64c7910f22e716b"
    ),
    public_key=bytes.fromhex(
        "e7f735ba19a33fd67323ab37262de536"
        "08ca578576534352e18f64e613d38d54"
    ),
    slot=PairingKeySlot.SLOT_0,
)

# Hardware wallet example keys (SH1) - from lt_ex_hw_wallet.c
# Used on devices configured with the HW wallet example
KEY_CONFIG_HWWALLET = KeyConfig(
    name="hwwallet",
    private_key=bytes.fromhex(
        "58c48188f8b1cbd419002e9c8df8ceea"
        "f3a911deb66bc887aee78810fb48b674"
    ),
    public_key=bytes.fromhex(
        "e1dcf9c346bcf2e78ba8f027d80a8a33"
        "ccf3e9df6bdf65a2c1aec4d921e18d51"
    ),
    slot=PairingKeySlot.SLOT_1,
)

# Map of available key configurations
KEY_CONFIGS = {
    "engineering": KEY_CONFIG_ENGINEERING,
    "hwwallet": KEY_CONFIG_HWWALLET,
}


def get_key_config() -> KeyConfig:
    """Get the active key configuration from environment variable."""
    config_name = os.environ.get("LIBTROPIC_KEY_CONFIG", "engineering").lower()
    if config_name not in KEY_CONFIGS:
        valid_options = ", ".join(KEY_CONFIGS.keys())
        raise ValueError(
            f"Invalid LIBTROPIC_KEY_CONFIG='{config_name}'. "
            f"Valid options: {valid_options}"
        )
    return KEY_CONFIGS[config_name]


# Legacy exports for backward compatibility (use engineering keys by default)
# Tests should use the key_config fixture instead for dynamic configuration
TEST_SH0_PRIV = KEY_CONFIG_ENGINEERING.private_key
TEST_SH0_PUB = KEY_CONFIG_ENGINEERING.public_key

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
def key_config() -> KeyConfig:
    """
    Get active key configuration based on LIBTROPIC_KEY_CONFIG env var.

    Returns:
        KeyConfig with private_key, public_key, and slot fields.

    Environment Variable:
        LIBTROPIC_KEY_CONFIG: "engineering" (default) or "hwwallet"
    """
    return get_key_config()


@pytest.fixture
def device() -> Generator[Tropic01, None, None]:
    """
    Provide initialized Tropic01 device (no session).

    Transport is selected via LIBTROPIC_TRANSPORT env var ("usb" or "spi").
    Use for tests that only need device-level operations.
    """
    transport = create_transport()
    dev = Tropic01(transport)
    dev.open()
    try:
        yield dev
    finally:
        dev.close()


@pytest.fixture
def device_with_session(key_config: KeyConfig) -> Generator[Tropic01, None, None]:
    """
    Provide Tropic01 device with active secure session.

    Transport is selected via LIBTROPIC_TRANSPORT env var ("usb" or "spi").

    Uses keys configured via LIBTROPIC_KEY_CONFIG environment variable:
        - "engineering": Engineering sample keys at slot 0 (default)
        - "hwwallet": Hardware wallet example keys at slot 1

    Use for tests that require L3 (session-protected) operations.
    """
    transport = create_transport()
    dev = Tropic01(transport)
    dev.open()
    dev.verify_chip_and_start_session(
        private_key=key_config.private_key,
        public_key=key_config.public_key,
        slot=key_config.slot
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
