"""
Main TROPIC01 device interface for libtropic.

Provides the primary entry point for communicating with TROPIC01 secure elements.
"""

from pathlib import Path
from typing import Optional, Union

from .enums import (
    DeviceMode,
    StartupMode,
    PairingKeySlot,
    FirmwareBank,
)
from .types import (
    ChipId,
    FirmwareVersion,
    FirmwareHeader,
    CertificateStore,
    X25519_KEY_LEN,
)
from .transport.base import Transport
from .transport.usb_dongle import UsbDongleTransport, UsbDongleConfig
from .transport.spi import LinuxSpiTransport, SpiConfig
from .crypto.ecc import EccKeys
from .crypto.random import RandomGenerator
from .storage.memory import DataMemory
from .storage.config import Configuration
from .counters import MonotonicCounters
from .mac_and_destroy import MacAndDestroy
from .pairing_keys import PairingKeys
from .firmware import FirmwareUpdater


class Tropic01:
    """
    Main interface for TROPIC01 secure element.

    This class provides access to all TROPIC01 functionality through a
    clean, Pythonic API. It manages the device connection, secure session,
    and provides access to sub-modules for specific operations.

    Transport Support:
        - Native Linux SPI (for Raspberry Pi, BeagleBone, etc.)
        - USB serial dongle (TS1302 evaluation kit)

    Basic Usage:
        # Simple connection via USB dongle
        with Tropic01("/dev/ttyACM0") as device:
            print(f"Mode: {device.mode.name}")
            print(f"Chip ID: {device.get_chip_id()}")

    With Secure Session:
        with Tropic01("/dev/ttyACM0") as device:
            # Start secure session (required for most operations)
            device.start_session(
                private_key=sh0_priv,
                public_key=sh0_pub,
                slot=0
            )

            # Now you can use cryptographic functions
            random_data = device.random.get_bytes(32)
            device.ecc.generate(slot=0, curve=EccCurve.ED25519)

    With Native SPI (Raspberry Pi):
        config = SpiConfig(
            spi_device="/dev/spidev0.0",
            gpio_chip="/dev/gpiochip0",
            cs_pin=8
        )
        transport = LinuxSpiTransport(config)

        with Tropic01(transport) as device:
            ...
    """

    def __init__(
        self,
        transport: Union[str, Path, Transport, None] = None
    ):
        """
        Initialize TROPIC01 device interface.

        Args:
            transport: Connection method, one of:
                - str/Path: Device path for USB dongle (e.g., "/dev/ttyACM0")
                - Transport: Pre-configured transport instance
                - None: Auto-detect (tries /dev/ttyACM0)

        Example:
            # USB dongle with auto-detect
            device = Tropic01()

            # USB dongle with explicit path
            device = Tropic01("/dev/ttyACM0")

            # Native SPI transport
            transport = LinuxSpiTransport(SpiConfig(...))
            device = Tropic01(transport)
        """
        if transport is None:
            transport = "/dev/ttyACM0"

        if isinstance(transport, (str, Path)):
            # String path = USB dongle transport
            config = UsbDongleConfig(device_path=str(transport))
            self._transport = UsbDongleTransport(config)
            self._owns_transport = True
        elif isinstance(transport, Transport):
            self._transport = transport
            self._owns_transport = False
        else:
            raise TypeError(f"Invalid transport type: {type(transport)}")

        self._is_open = False
        self._has_session = False

        # Sub-modules (lazily initialized)
        self._ecc: Optional[EccKeys] = None
        self._random: Optional[RandomGenerator] = None
        self._memory: Optional[DataMemory] = None
        self._config: Optional[Configuration] = None
        self._counters: Optional[MonotonicCounters] = None
        self._mac_and_destroy: Optional[MacAndDestroy] = None
        self._pairing_keys: Optional[PairingKeys] = None
        self._firmware: Optional[FirmwareUpdater] = None

    # =========================================================================
    # Context Manager
    # =========================================================================

    def __enter__(self) -> 'Tropic01':
        """Context manager entry - opens connection and initializes device."""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - closes connection and releases resources."""
        self.close()

    def open(self) -> None:
        """
        Open connection and initialize device.

        Called automatically when using context manager.

        Raises:
            ConnectionError: If transport cannot be opened
            TropicError: If device initialization fails

        Maps to: lt_init()
        """
        raise NotImplementedError()

    def close(self) -> None:
        """
        Close connection and release resources.

        Aborts any active session and closes the transport.
        Called automatically when using context manager.

        Maps to: lt_deinit()
        """
        raise NotImplementedError()

    # =========================================================================
    # Device Information
    # =========================================================================

    @property
    def mode(self) -> DeviceMode:
        """
        Get current device operating mode.

        Returns:
            Current mode (MAINTENANCE, APPLICATION, or ALARM)

        Raises:
            TropicError: If mode cannot be determined

        Maps to: lt_get_tr01_mode()
        """
        raise NotImplementedError()

    def get_chip_id(self) -> ChipId:
        """
        Read chip identification data.

        Returns device serial number, version info, and manufacturing data.

        Returns:
            ChipId containing all identification fields

        Maps to: lt_get_info_chip_id()
        """
        raise NotImplementedError()

    def get_riscv_firmware_version(self) -> FirmwareVersion:
        """
        Get RISC-V CPU firmware version.

        Returns:
            FirmwareVersion with version numbers

        Maps to: lt_get_info_riscv_fw_ver()
        """
        raise NotImplementedError()

    def get_spect_firmware_version(self) -> FirmwareVersion:
        """
        Get SPECT coprocessor firmware version.

        Returns:
            FirmwareVersion with version numbers

        Maps to: lt_get_info_spect_fw_ver()
        """
        raise NotImplementedError()

    def get_firmware_header(self, bank: FirmwareBank) -> FirmwareHeader:
        """
        Read firmware bank header (maintenance mode only).

        Args:
            bank: Firmware bank to read (FW1, FW2, SPECT1, or SPECT2)

        Returns:
            FirmwareHeader with bank information

        Raises:
            TropicError: If not in maintenance mode
            ParamError: If bank is invalid

        Maps to: lt_get_info_fw_bank()
        """
        raise NotImplementedError()

    def get_certificate_store(self) -> CertificateStore:
        """
        Read X.509 certificate chain from device.

        Returns the full PKI chain including device, intermediate,
        TROPIC01, and root certificates.

        Returns:
            CertificateStore containing all certificates

        Maps to: lt_get_info_cert_store()
        """
        raise NotImplementedError()

    def get_device_public_key(self) -> bytes:
        """
        Extract device public key (ST_Pub) from certificate store.

        Returns the X25519 public key used for secure session establishment.

        Returns:
            32-byte X25519 public key

        Maps to: lt_get_st_pub()
        """
        raise NotImplementedError()

    # =========================================================================
    # Device Control
    # =========================================================================

    def reboot(self, mode: StartupMode = StartupMode.REBOOT) -> None:
        """
        Reboot device into specified mode.

        Args:
            mode: Target mode after reboot:
                  - REBOOT: Normal reboot to application mode
                  - MAINTENANCE_REBOOT: Reboot to bootloader mode

        Raises:
            RebootError: If reboot to requested mode fails

        Maps to: lt_reboot()
        """
        raise NotImplementedError()

    def sleep(self) -> None:
        """
        Put device into sleep mode.

        Low-power sleep state. Device wakes on next SPI transaction.

        Maps to: lt_sleep()
        """
        raise NotImplementedError()

    # =========================================================================
    # Secure Session
    # =========================================================================

    def start_session(
        self,
        private_key: bytes,
        public_key: bytes,
        slot: Union[int, PairingKeySlot] = 0
    ) -> None:
        """
        Establish encrypted secure session.

        Performs X25519 key exchange with the device to establish an
        encrypted communication channel. Most operations require an
        active session.

        Args:
            private_key: 32-byte X25519 private key (host pairing key)
            public_key: 32-byte X25519 public key (host pairing key)
            slot: Pairing key slot index (0-3) where public_key is stored

        Raises:
            ParamError: If keys are invalid or slot out of range
            HandshakeError: If key exchange fails

        Maps to: lt_session_start()
        """
        raise NotImplementedError()

    def abort_session(self) -> None:
        """
        Terminate current secure session.

        Invalidates session keys on both host and device. A new session
        must be started before using session-protected operations.

        Maps to: lt_session_abort()
        """
        raise NotImplementedError()

    @property
    def has_session(self) -> bool:
        """Check if a secure session is currently active."""
        return self._has_session

    def ping(self, data: bytes) -> bytes:
        """
        Echo test through secure channel.

        Sends data through the encrypted channel and receives it back.
        Useful for verifying session is working correctly.

        Args:
            data: Data to echo (max 255 bytes)

        Returns:
            Echoed data (should match input)

        Raises:
            NoSessionError: If no secure session is active
            ParamError: If data exceeds maximum length

        Maps to: lt_ping()
        """
        raise NotImplementedError()

    # =========================================================================
    # Logging (Debug)
    # =========================================================================

    def get_log(self) -> bytes:
        """
        Get debug log message from RISC-V firmware.

        Only available if logging is enabled in device configuration.
        Production devices typically have logging disabled.

        Returns:
            Log message bytes (up to 255 bytes)

        Note:
            This is primarily for internal debugging and may not be
            available on production devices.

        Maps to: lt_get_log_req()
        """
        raise NotImplementedError()

    # =========================================================================
    # Sub-modules (Lazy Initialization)
    # =========================================================================

    @property
    def ecc(self) -> EccKeys:
        """
        ECC key operations (generate, store, read, erase, sign).

        Provides access to 32 ECC key slots supporting P256 and Ed25519.
        """
        if self._ecc is None:
            self._ecc = EccKeys(self)
        return self._ecc

    @property
    def random(self) -> RandomGenerator:
        """
        Hardware random number generator.

        Provides cryptographically secure random bytes from TROPIC01's RNG.
        """
        if self._random is None:
            self._random = RandomGenerator(self)
        return self._random

    @property
    def memory(self) -> DataMemory:
        """
        User data storage in R-Memory.

        Provides 512 slots for storing arbitrary data.
        """
        if self._memory is None:
            self._memory = DataMemory(self)
        return self._memory

    @property
    def config(self) -> Configuration:
        """
        Device configuration (R-Config and I-Config).

        Controls User Access Privileges and device settings.
        """
        if self._config is None:
            self._config = Configuration(self)
        return self._config

    @property
    def counters(self) -> MonotonicCounters:
        """
        Hardware monotonic counters.

        Provides 16 counters that can only count down.
        """
        if self._counters is None:
            self._counters = MonotonicCounters(self)
        return self._counters

    @property
    def mac_and_destroy(self) -> MacAndDestroy:
        """
        MAC-and-Destroy secure verification.

        Provides 128 slots for hardware-backed PIN/password verification.
        """
        if self._mac_and_destroy is None:
            self._mac_and_destroy = MacAndDestroy(self)
        return self._mac_and_destroy

    @property
    def pairing_keys(self) -> PairingKeys:
        """
        Pairing key management.

        Manages 4 X25519 pairing key slots for session establishment.
        """
        if self._pairing_keys is None:
            self._pairing_keys = PairingKeys(self)
        return self._pairing_keys

    @property
    def firmware(self) -> FirmwareUpdater:
        """
        Firmware update operations (maintenance mode only).
        """
        if self._firmware is None:
            self._firmware = FirmwareUpdater(self)
        return self._firmware

    # =========================================================================
    # Representation
    # =========================================================================

    def __repr__(self) -> str:
        status = "open" if self._is_open else "closed"
        session = "session active" if self._has_session else "no session"
        return f"<Tropic01 {status}, {session}>"
