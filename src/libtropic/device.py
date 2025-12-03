"""
Main TROPIC01 device interface for libtropic.

Provides the primary entry point for communicating with TROPIC01 secure elements.
"""

from pathlib import Path
from types import TracebackType

from .counters import MonotonicCounters
from .crypto.ecc import EccKeys
from .crypto.random import RandomGenerator
from .enums import (
    DeviceMode,
    FirmwareBank,
    PairingKeySlot,
    ReturnCode,
    StartupMode,
)
from .exceptions import (
    DeviceAlarmError,
    RebootError,
    TropicError,
)
from .firmware import FirmwareUpdater
from .mac_and_destroy import MacAndDestroy
from .pairing_keys import PairingKeys
from .storage.config import Configuration
from .storage.memory import DataMemory
from .transport.base import Transport
from .transport.usb_dongle import UsbDongleConfig, UsbDongleTransport
from .types import (
    CertificateStore,
    ChipId,
    FirmwareHeader,
    FirmwareVersion,
)
from ._protocol import (
    L2Layer,
    L1_CHIP_MODE_READY,
    L1_CHIP_MODE_ALARM,
    L1_CHIP_MODE_STARTUP,
    L2_GET_INFO_REQ_ID,
    L2_STARTUP_REQ_ID,
    L2_SLEEP_REQ_ID,
    L2_GET_LOG_REQ_ID,
    L2_GET_INFO_OBJECT_ID_CHIP_ID,
    L2_GET_INFO_OBJECT_ID_RISCV_FW_VER,
    L2_GET_INFO_OBJECT_ID_SPECT_FW_VER,
    L2_GET_INFO_OBJECT_ID_FW_BANK,
    STARTUP_ID_REBOOT,
    STARTUP_ID_MAINTENANCE,
    SLEEP_KIND_SLEEP,
    REBOOT_DELAY_MS,
)
from ._protocol.l1 import L1ChipAlarm


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
        transport: str | Path | Transport | None = None
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

        self._transport: Transport
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

        # Protocol layers (initialized on open)
        self._l2: L2Layer | None = None

        # Sub-modules (lazily initialized)
        self._ecc: EccKeys | None = None
        self._random: RandomGenerator | None = None
        self._memory: DataMemory | None = None
        self._config: Configuration | None = None
        self._counters: MonotonicCounters | None = None
        self._mac_and_destroy: MacAndDestroy | None = None
        self._pairing_keys: PairingKeys | None = None
        self._firmware: FirmwareUpdater | None = None

    # =========================================================================
    # Context Manager
    # =========================================================================

    def __enter__(self) -> 'Tropic01':
        """Context manager entry - opens connection and initializes device."""
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None
    ) -> None:
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
        if self._is_open:
            return

        # Open the transport (USB dongle, SPI, etc.)
        self._transport.open()

        # Initialize L2 protocol layer
        self._l2 = L2Layer(self._transport)

        self._is_open = True

    def close(self) -> None:
        """
        Close connection and release resources.

        Aborts any active session and closes the transport.
        Called automatically when using context manager.

        Maps to: lt_deinit()
        """
        if not self._is_open:
            return

        # Abort session if active (ignore errors during cleanup)
        if self._has_session:
            try:
                self.abort_session()
            except Exception:
                pass

        # Clear session state
        self._has_session = False
        self._l2 = None

        # Close transport if we own it
        if self._owns_transport:
            try:
                self._transport.close()
            except Exception:
                pass

        self._is_open = False

    # =========================================================================
    # Device Information
    # =========================================================================

    def _ensure_open(self) -> L2Layer:
        """Ensure device is open and return L2 layer."""
        if not self._is_open or self._l2 is None:
            raise RuntimeError("Device not open. Call open() first or use as context manager.")
        return self._l2

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
        l2 = self._ensure_open()

        try:
            chip_status = l2.l1.get_chip_status()
        except L1ChipAlarm:
            return DeviceMode.ALARM

        # Check ALARM bit first (highest priority)
        if chip_status & L1_CHIP_MODE_ALARM:
            return DeviceMode.ALARM

        # Check if chip is ready
        if chip_status & L1_CHIP_MODE_READY:
            # Check STARTUP bit to distinguish modes
            if chip_status & L1_CHIP_MODE_STARTUP:
                return DeviceMode.MAINTENANCE
            else:
                return DeviceMode.APPLICATION

        # Chip is busy/not ready - default to application mode
        return DeviceMode.APPLICATION

    def _get_info(self, object_id: int, block_index: int = 0) -> bytes:
        """
        Send GET_INFO L2 request and return response data.

        Args:
            object_id: Object identifier to request
            block_index: Block index for multi-block objects (certificates)

        Returns:
            Response data bytes
        """
        l2 = self._ensure_open()
        # Build request data: [OBJECT_ID, BLOCK_INDEX]
        request_data = bytes([object_id, block_index])
        response = l2.send_receive(L2_GET_INFO_REQ_ID, request_data)
        return response.data

    def get_chip_id(self) -> ChipId:
        """
        Read chip identification data.

        Returns device serial number, version info, and manufacturing data.

        Returns:
            ChipId containing all identification fields

        Maps to: lt_get_info_chip_id()
        """
        data = self._get_info(L2_GET_INFO_OBJECT_ID_CHIP_ID)

        if len(data) < 128:
            raise TropicError(ReturnCode.FAIL, f"Chip ID data too short: {len(data)} bytes")

        # Parse CHIP_ID structure (128 bytes total)
        # See lt_chip_id_t in libtropic_common.h
        return ChipId(
            chip_id_version=data[0:4],
            fl_chip_info=data[4:20],
            func_test_info=data[20:28],
            silicon_rev=data[28:32].decode('ascii', errors='replace').rstrip('\x00'),
            package_type_id=int.from_bytes(data[32:34], 'little'),
            # rfu_1 at 34:36
            provisioning_version=data[36],
            fab_id=((data[37] & 0x0F) << 8) | data[38],  # 12 bits
            short_part_number=((data[37] & 0xF0) >> 4) | (data[39] << 4),  # 12 bits
            provisioning_date=data[40:42],
            hsm_version=data[42:46],
            programmer_version=data[46:50],
            # rfu_2 at 50:52
            serial_number=data[52:68],
            part_number=data[68:84].decode('ascii', errors='replace').rstrip('\x00'),
            prov_template_version=(data[84], data[85]),
            prov_template_tag=data[86:90],
            prov_spec_version=(data[90], data[91]),
            prov_spec_tag=data[92:96],
            batch_id=data[96:101],
            # rfu_3 at 101:104
            # rfu_4 at 104:128
        )

    def get_riscv_firmware_version(self) -> FirmwareVersion:
        """
        Get RISC-V CPU firmware version.

        Returns:
            FirmwareVersion with version numbers

        Maps to: lt_get_info_riscv_fw_ver()
        """
        data = self._get_info(L2_GET_INFO_OBJECT_ID_RISCV_FW_VER)

        if len(data) < 4:
            raise TropicError(ReturnCode.FAIL, f"RISC-V FW version data too short: {len(data)} bytes")

        # Version is 4 bytes: [major, minor, patch, build]
        # Note: If in startup mode, highest bit is set
        version = int.from_bytes(data[0:4], 'big')
        is_bootloader = bool(version & 0x80000000)
        version &= 0x7FFFFFFF  # Clear startup flag

        return FirmwareVersion(
            major=(version >> 24) & 0xFF,
            minor=(version >> 16) & 0xFF,
            patch=(version >> 8) & 0xFF,
            build=version & 0xFF,
        )

    def get_spect_firmware_version(self) -> FirmwareVersion:
        """
        Get SPECT coprocessor firmware version.

        Returns:
            FirmwareVersion with version numbers

        Maps to: lt_get_info_spect_fw_ver()
        """
        data = self._get_info(L2_GET_INFO_OBJECT_ID_SPECT_FW_VER)

        if len(data) < 4:
            raise TropicError(ReturnCode.FAIL, f"SPECT FW version data too short: {len(data)} bytes")

        # Version is 4 bytes: [major, minor, patch, build]
        # Note: If in startup mode, this returns 0x80000000 (dummy value)
        version = int.from_bytes(data[0:4], 'big')
        version &= 0x7FFFFFFF  # Clear startup flag

        return FirmwareVersion(
            major=(version >> 24) & 0xFF,
            minor=(version >> 16) & 0xFF,
            patch=(version >> 8) & 0xFF,
            build=version & 0xFF,
        )

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
        # Request FW bank header (bank ID is used as block_index)
        data = self._get_info(L2_GET_INFO_OBJECT_ID_FW_BANK, block_index=int(bank))

        if len(data) == 0:
            # Empty bank
            return FirmwareHeader(
                fw_type=0,
                version=0,
                size=0,
                git_hash=b'\x00' * 4,
                content_hash=b'\x00' * 32,
                header_version=0,
            )

        if len(data) == 20:
            # Boot v1 header (20 bytes)
            return FirmwareHeader(
                fw_type=int.from_bytes(data[0:4], 'little'),
                version=int.from_bytes(data[4:8], 'little'),
                size=int.from_bytes(data[8:12], 'little'),
                git_hash=data[12:16],
                content_hash=data[16:20] + b'\x00' * 28,  # Only 4 bytes in v1
                header_version=1,
            )

        if len(data) >= 52:
            # Boot v2 header (52 bytes)
            return FirmwareHeader(
                fw_type=int.from_bytes(data[0:2], 'little'),
                header_version=data[3],
                version=int.from_bytes(data[4:8], 'little'),
                size=int.from_bytes(data[8:12], 'little'),
                git_hash=data[12:16],
                content_hash=data[16:48],
                pair_version=int.from_bytes(data[48:52], 'little'),
            )

        raise TropicError(ReturnCode.FAIL, f"Unexpected FW header size: {len(data)} bytes")

    def get_certificate_store(self) -> CertificateStore:
        """
        Read X.509 certificate chain from device.

        Returns the full PKI chain including device, intermediate,
        TROPIC01, and root certificates.

        Returns:
            CertificateStore containing all certificates

        Maps to: lt_get_info_cert_store()
        """
        # TODO: Implement certificate store reading with proper ASN.1 parsing
        # This requires reading multiple 128-byte blocks and parsing the
        # certificate store header to determine certificate boundaries
        raise NotImplementedError("Certificate store reading not yet implemented")

    def get_device_public_key(self) -> bytes:
        """
        Extract device public key (ST_Pub) from certificate store.

        Returns the X25519 public key used for secure session establishment.

        Returns:
            32-byte X25519 public key

        Maps to: lt_get_st_pub()
        """
        # TODO: Implement by parsing device certificate from get_certificate_store()
        raise NotImplementedError("Device public key extraction not yet implemented")

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
        l2 = self._ensure_open()

        # Map StartupMode enum to protocol constants
        if mode == StartupMode.REBOOT:
            startup_id = STARTUP_ID_REBOOT
            expected_mode = DeviceMode.APPLICATION
        else:
            startup_id = STARTUP_ID_MAINTENANCE
            expected_mode = DeviceMode.MAINTENANCE

        # Mark that we're sending a startup request (for L2 erratum workaround)
        l2.mark_startup_sent()

        # Send STARTUP request
        l2.send_receive(L2_STARTUP_REQ_ID, bytes([startup_id]))

        # Clear session state (reboot invalidates session)
        self._has_session = False

        # Wait for device to reboot
        self._transport.delay_ms(REBOOT_DELAY_MS)

        # Verify device is in expected mode
        actual_mode = self.mode
        if actual_mode != expected_mode:
            raise RebootError(
                ReturnCode.REBOOT_UNSUCCESSFUL,
                f"Expected {expected_mode.name}, got {actual_mode.name}"
            )

    def sleep(self) -> None:
        """
        Put device into sleep mode.

        Low-power sleep state. Device wakes on next SPI transaction.

        Maps to: lt_sleep()
        """
        l2 = self._ensure_open()

        # Send SLEEP request with sleep kind
        l2.send_receive(L2_SLEEP_REQ_ID, bytes([SLEEP_KIND_SLEEP]))

    # =========================================================================
    # Secure Session
    # =========================================================================

    def start_session(
        self,
        private_key: bytes,
        public_key: bytes,
        slot: int | PairingKeySlot = 0
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
        # TODO: Implement secure session establishment with X25519 handshake
        # This requires:
        # 1. Generate ephemeral X25519 keypair
        # 2. Send HANDSHAKE L2 request with ephemeral public key
        # 3. Receive device ephemeral public key and auth tag
        # 4. Derive session keys using HKDF
        # 5. Verify auth tag
        # 6. Store session keys for L3 encryption
        raise NotImplementedError("Session start not yet implemented")

    def abort_session(self) -> None:
        """
        Terminate current secure session.

        Invalidates session keys on both host and device. A new session
        must be started before using session-protected operations.

        Maps to: lt_session_abort()
        """
        from ._protocol.constants import L2_SESSION_ABORT_REQ_ID

        l2 = self._ensure_open()

        # Only send abort if we think we have a session
        if self._has_session:
            try:
                l2.send_receive(L2_SESSION_ABORT_REQ_ID, b"")
            except Exception:
                pass  # Ignore errors during abort

        # Clear session state
        self._has_session = False

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
        # TODO: Implement ping through L3 encrypted channel
        # This requires an active session and L3 command encoding
        raise NotImplementedError("Ping not yet implemented (requires session)")

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
        l2 = self._ensure_open()
        response = l2.send_receive(L2_GET_LOG_REQ_ID, b"")
        return response.data

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
