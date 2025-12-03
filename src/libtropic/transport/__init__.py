"""
Transport layer implementations for libtropic.

Provides various backends for communicating with TROPIC01:
- LinuxSpiTransport: Native SPI via spidev + GPIO
- UsbDongleTransport: USB serial bridge (TS1302 evaluation kit)
"""

from .base import Transport
from .spi import LinuxSpiTransport, SpiConfig
from .usb_dongle import UsbDongleConfig, UsbDongleTransport

__all__ = [
    "Transport",
    "LinuxSpiTransport",
    "SpiConfig",
    "UsbDongleTransport",
    "UsbDongleConfig",
]
