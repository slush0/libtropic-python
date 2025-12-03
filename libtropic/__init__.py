"""
libtropic - Python bindings for TROPIC01 secure element.

This package provides a Pythonic interface to the TROPIC01 secure element
from Tropic Square. It supports multiple transport backends and provides
access to all device functionality.

Quick Start:
    from libtropic import Tropic01, EccCurve

    with Tropic01("/dev/ttyACM0") as device:
        # Start secure session
        device.start_session(private_key, public_key, slot=0)

        # Generate ECC key
        device.ecc.generate(slot=0, curve=EccCurve.ED25519)

        # Get random bytes
        random_data = device.random.get_bytes(32)

Transport Options:
    - USB dongle (TS1302): Pass device path string
    - Native Linux SPI: Use LinuxSpiTransport with SpiConfig

See documentation for full API reference.
"""

__version__ = "0.1.0"
__author__ = "Tropic Square"

# Main device class
from .device import Tropic01

# Enumerations
from .enums import (
    ReturnCode,
    DeviceMode,
    StartupMode,
    EccCurve,
    EccKeyOrigin,
    FirmwareBank,
    PairingKeySlot,
    EccSlot,
    McounterIndex,
    MacAndDestroySlot,
    ConfigAddress,
    CertKind,
)

# Data types
from .types import (
    ChipId,
    FirmwareVersion,
    FirmwareHeader,
    CertificateStore,
    EccKeyInfo,
    DeviceConfig,
    SerialNumber,
)

# Exceptions
from .exceptions import (
    TropicError,
    NoSessionError,
    ParamError,
    CryptoError,
    DeviceAlarmError,
    UnauthorizedError,
    SlotError,
    SlotEmptyError,
    SlotNotEmptyError,
    SlotExpiredError,
    SlotInvalidError,
    InvalidKeyError,
    CounterInvalidError,
    HardwareError,
    HandshakeError,
    AuthenticationError,
    CrcError,
    CertificateError,
    RebootError,
    TransportError,
    TimeoutError,
    ConnectionError,
)

# Transport layer
from .transport import (
    Transport,
    LinuxSpiTransport,
    SpiConfig,
    UsbDongleTransport,
    UsbDongleConfig,
)

# Factory functions for common configurations
def connect_usb_dongle(
    device_path: str = "/dev/ttyACM0",
    baud_rate: int = 115200
) -> Tropic01:
    """
    Connect to TROPIC01 via USB serial dongle (TS1302).

    This is the simplest way to connect using the evaluation kit.

    Args:
        device_path: Serial device path
            - Linux: /dev/ttyACM0 or /dev/ttyUSB0
            - macOS: /dev/cu.usbmodem* or /dev/tty.usbmodem*
            - Windows: COM3, COM4, etc.
        baud_rate: UART baud rate (default: 115200)

    Returns:
        Tropic01 device instance (use as context manager)

    Example:
        with connect_usb_dongle("/dev/ttyACM0") as device:
            print(device.mode)
    """
    config = UsbDongleConfig(device_path=device_path, baud_rate=baud_rate)
    transport = UsbDongleTransport(config)
    return Tropic01(transport)


def connect_spi(
    spi_device: str = "/dev/spidev0.0",
    spi_speed_hz: int = 1_000_000,
    gpio_chip: str = "/dev/gpiochip0",
    cs_pin: int = 8,
    int_pin: int = None
) -> Tropic01:
    """
    Connect to TROPIC01 via native Linux SPI.

    For Raspberry Pi, BeagleBone, and other Linux SBCs with SPI/GPIO.

    Args:
        spi_device: Path to SPI device (e.g., "/dev/spidev0.0")
        spi_speed_hz: SPI clock speed in Hz (default: 1 MHz)
        gpio_chip: Path to GPIO chip (e.g., "/dev/gpiochip0")
        cs_pin: GPIO pin number for chip select
        int_pin: Optional GPIO pin for interrupt (None to disable)

    Returns:
        Tropic01 device instance (use as context manager)

    Example (Raspberry Pi):
        with connect_spi(
            spi_device="/dev/spidev0.0",
            gpio_chip="/dev/gpiochip0",
            cs_pin=8,
            int_pin=25
        ) as device:
            print(device.mode)
    """
    config = SpiConfig(
        spi_device=spi_device,
        spi_speed_hz=spi_speed_hz,
        gpio_chip=gpio_chip,
        cs_pin=cs_pin,
        int_pin=int_pin
    )
    transport = LinuxSpiTransport(config)
    return Tropic01(transport)


__all__ = [
    # Main class
    "Tropic01",

    # Factory functions
    "connect_usb_dongle",
    "connect_spi",

    # Enumerations
    "ReturnCode",
    "DeviceMode",
    "StartupMode",
    "EccCurve",
    "EccKeyOrigin",
    "FirmwareBank",
    "PairingKeySlot",
    "EccSlot",
    "McounterIndex",
    "MacAndDestroySlot",
    "ConfigAddress",
    "CertKind",

    # Data types
    "ChipId",
    "FirmwareVersion",
    "FirmwareHeader",
    "CertificateStore",
    "EccKeyInfo",
    "DeviceConfig",
    "SerialNumber",

    # Exceptions
    "TropicError",
    "NoSessionError",
    "ParamError",
    "CryptoError",
    "DeviceAlarmError",
    "UnauthorizedError",
    "SlotError",
    "SlotEmptyError",
    "SlotNotEmptyError",
    "SlotExpiredError",
    "SlotInvalidError",
    "InvalidKeyError",
    "CounterInvalidError",
    "HardwareError",
    "HandshakeError",
    "AuthenticationError",
    "CrcError",
    "CertificateError",
    "RebootError",
    "TransportError",
    "TimeoutError",
    "ConnectionError",

    # Transport
    "Transport",
    "LinuxSpiTransport",
    "SpiConfig",
    "UsbDongleTransport",
    "UsbDongleConfig",
]
