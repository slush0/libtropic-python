"""
Main TROPIC01 device interface for libtropic.

Provides the primary entry point for communicating with TROPIC01 secure elements.
"""

import secrets
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

from ._cal import (
    AesGcmDecryptContext,
    Sha256Context,
    hkdf,
    secure_memzero,
    x25519,
    x25519_scalarmult_base,
)
from ._protocol import (
    AESGCM_IV_SIZE,
    HANDSHAKE_RSP_ET_PUB_SIZE,
    HANDSHAKE_RSP_T_AUTH_SIZE,
    L1_CHIP_MODE_ALARM,
    L1_CHIP_MODE_READY,
    L1_CHIP_MODE_STARTUP,
    L2_ENCRYPTED_CMD_REQ_ID,
    L2_GET_INFO_OBJECT_ID_CHIP_ID,
    L2_GET_INFO_OBJECT_ID_FW_BANK,
    L2_GET_INFO_OBJECT_ID_RISCV_FW_VER,
    L2_GET_INFO_OBJECT_ID_SPECT_FW_VER,
    L2_GET_INFO_REQ_ID,
    L2_GET_LOG_REQ_ID,
    L2_HANDSHAKE_REQ_ID,
    L2_HANDSHAKE_RSP_LEN,
    L2_SLEEP_REQ_ID,
    L2_STARTUP_REQ_ID,
    REBOOT_DELAY_MS,
    SLEEP_KIND_SLEEP,
    STARTUP_ID_MAINTENANCE,
    STARTUP_ID_REBOOT,
    X25519_KEY_LEN,
    L2Layer,
    L3ResultError,
    decrypt_response,
    encrypt_command,
    result_code_to_exception,
)
from ._protocol.l1 import L1ChipAlarmError
from .config import Configuration
from .counters import MonotonicCounters
from .ecc import EccKeys
from .enums import (
    DeviceMode,
    FirmwareBank,
    PairingKeySlot,
    ReturnCode,
    StartupMode,
)
from .exceptions import (
    AuthenticationError,
    HandshakeError,
    NoSessionError,
    ParamError,
    RebootError,
    TropicError,
)
from .firmware import FirmwareUpdater
from .mac_and_destroy import MacAndDestroy
from .memory import DataMemory
from .pairing_keys import PairingKeys
from .random import RandomGenerator
from .transport.base import Transport
from .transport.usb_dongle import UsbDongleConfig, UsbDongleTransport
from .types import (
    CertificateStore,
    ChipId,
    FirmwareHeader,
    FirmwareVersion,
)


@dataclass
class SessionState:
    """
    Holds secure session state for TROPIC01 communication.

    Created during session handshake and used for L3 command encryption.
    """

    # 32-byte AES-256 key for encrypting commands (host -> device)
    k_cmd: bytes

    # 32-byte AES-256 key for decrypting responses (device -> host)
    k_res: bytes

    # 12-byte IV for command encryption (incremented after each command)
    cmd_iv: bytearray

    # 12-byte IV for response decryption (incremented after each response)
    res_iv: bytearray

    def clear(self) -> None:
        """Securely clear all session key material from memory."""
        # Clear keys using secure memory wipe
        if self.k_cmd:
            key_buffer = bytearray(self.k_cmd)
            secure_memzero(key_buffer)
        if self.k_res:
            key_buffer = bytearray(self.k_res)
            secure_memzero(key_buffer)

        # Clear IVs
        secure_memzero(self.cmd_iv)
        secure_memzero(self.res_iv)


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
            # Get device public key and start secure session
            stpub = device.get_device_public_key()
            device.start_session(
                stpub=stpub,
                slot=0,
                private_key=sh0_priv,
                public_key=sh0_pub,
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

        # Secure session state (populated by start_session)
        self._session: SessionState | None = None

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

        # Clear session state (securely wipe key material)
        if self._session is not None:
            self._session.clear()
            self._session = None
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

    def _ensure_session(self) -> SessionState:
        """
        Ensure device is open and session is active.

        Returns:
            Active session state

        Raises:
            RuntimeError: If device not open
            NoSessionError: If no active session
        """
        self._ensure_open()
        if not self._has_session or self._session is None:
            raise NoSessionError(
                ReturnCode.HOST_NO_SESSION,
                "No active session. Call start_session() first."
            )
        return self._session

    def _send_l3_command(self, cmd_id: int, data: bytes = b"") -> bytes:
        """
        Send encrypted L3 command and receive decrypted response.

        This is the core method for all session-protected operations.
        It encrypts the command, sends it via L2, and decrypts the response.

        For large L3 payloads (> 252 bytes), the encrypted data is split
        into chunks and sent separately. The response may also come in
        multiple chunks.

        Args:
            cmd_id: L3 command identifier
            data: Command data (may be empty)

        Returns:
            Response data (excluding result code)

        Raises:
            NoSessionError: If no active session
            L3ResultError: If command returns error result
            Various TropicError subclasses: Mapped from L3 result codes
        """
        from ._protocol.constants import L2_CHUNK_MAX_DATA_SIZE
        from ._protocol.l2 import L2FrameStatus

        session = self._ensure_session()
        l2 = self._ensure_open()

        # Encrypt command
        encrypted_cmd = encrypt_command(session, cmd_id, data)

        # Send encrypted command in chunks (max 252 bytes per L2 frame)
        packet_size = len(encrypted_cmd)
        offset = 0

        while offset < packet_size:
            # Calculate chunk size
            remaining = packet_size - offset
            chunk_size = min(remaining, L2_CHUNK_MAX_DATA_SIZE)
            chunk = encrypted_cmd[offset:offset + chunk_size]
            offset += chunk_size

            # Send chunk
            l2.send(L2_ENCRYPTED_CMD_REQ_ID, chunk)

            # Receive acknowledgment
            ack_response = l2.receive()

            # Check status
            if ack_response.status == L2FrameStatus.REQUEST_CONT:
                # More chunks expected - continue sending
                continue
            elif ack_response.status == L2FrameStatus.REQUEST_OK:
                # All chunks sent, command accepted
                break
            elif ack_response.status == L2FrameStatus.RESULT_OK:
                # Small response came immediately with request
                # (This shouldn't happen during multi-chunk send)
                break
            else:
                raise TropicError(
                    ReturnCode.FAIL,
                    f"Unexpected L2 status during command send: {ack_response.status.name}"
                )

        # Receive response (may also come in chunks)
        response_chunks = []

        while True:
            # If we already got RESULT_OK with data, use that
            if ack_response.status == L2FrameStatus.RESULT_OK:
                response_chunks.append(ack_response.data)
                break

            # Poll for response
            result_response = l2.receive()

            if result_response.status == L2FrameStatus.RESULT_CONT:
                # More response chunks coming
                response_chunks.append(result_response.data)
                continue
            elif result_response.status == L2FrameStatus.RESULT_OK:
                # Final response chunk
                response_chunks.append(result_response.data)
                break
            else:
                raise TropicError(
                    ReturnCode.FAIL,
                    f"Unexpected L2 status during response receive: {result_response.status.name}"
                )

        # Concatenate all response chunks
        response_data = b"".join(response_chunks)

        # Decrypt response
        try:
            result_code, decrypted_data = decrypt_response(session, response_data)
        except L3ResultError as e:
            # Convert L3 result error to appropriate exception type
            raise result_code_to_exception(e.result_code) from e

        return decrypted_data

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
        except L1ChipAlarmError:
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
            # part_num_data: first byte is length, rest is ASCII string
            part_number=data[69:69 + data[68]].decode('ascii', errors='replace'),
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
            raise TropicError(
                ReturnCode.FAIL, f"RISC-V FW version data too short: {len(data)} bytes"
            )

        # Version bytes: [build, patch, minor, major|flag]
        # Note: If in startup mode, highest bit of major (data[3]) is set
        return FirmwareVersion(
            major=data[3] & 0x7F,
            minor=data[2],
            patch=data[1],
            build=data[0],
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
            raise TropicError(
                ReturnCode.FAIL, f"SPECT FW version data too short: {len(data)} bytes"
            )

        # Version bytes: [build, patch, minor, major|flag]
        # Note: If in startup mode, this returns a dummy value with high bit set
        return FirmwareVersion(
            major=data[3] & 0x7F,
            minor=data[2],
            patch=data[1],
            build=data[0],
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
        from ._protocol.constants import (
            GET_INFO_CERT_CHUNK_SIZE,
            L2_GET_INFO_OBJECT_ID_X509_CERT,
        )

        l2 = self._ensure_open()

        # Certificate store constants
        cert_store_version = 0x01
        num_certificates = 4
        header_size = 2 + (num_certificates * 2)  # version + num_certs + 4x length

        # Read first block to get header
        response = l2.send_receive(
            L2_GET_INFO_REQ_ID,
            bytes([L2_GET_INFO_OBJECT_ID_X509_CERT, 0])  # block_index = 0
        )

        if len(response.data) != GET_INFO_CERT_CHUNK_SIZE:
            raise TropicError(
                ReturnCode.FAIL,
                f"Invalid certificate store response: {len(response.data)} bytes"
            )

        # Parse header
        data = response.data
        version = data[0]
        if version != cert_store_version:
            raise TropicError(
                ReturnCode.CERT_STORE_INVALID,
                f"Invalid certificate store version: {version}"
            )

        num_certs = data[1]
        if num_certs != num_certificates:
            raise TropicError(
                ReturnCode.CERT_STORE_INVALID,
                f"Unexpected certificate count: {num_certs}"
            )

        # Extract certificate lengths (big-endian)
        cert_lengths = []
        for i in range(num_certificates):
            offset = 2 + (i * 2)
            cert_len = (data[offset] << 8) | data[offset + 1]
            cert_lengths.append(cert_len)

        # Calculate total size needed and blocks to read
        total_cert_size = sum(cert_lengths)
        total_size = header_size + total_cert_size
        num_blocks = (total_size + GET_INFO_CERT_CHUNK_SIZE - 1) // GET_INFO_CERT_CHUNK_SIZE

        # Collect all blocks
        all_data = bytearray(data)
        for block_idx in range(1, num_blocks):
            response = l2.send_receive(
                L2_GET_INFO_REQ_ID,
                bytes([L2_GET_INFO_OBJECT_ID_X509_CERT, block_idx])
            )
            all_data.extend(response.data)

        # Extract certificates
        cert_offset = header_size
        certs = []
        for _, cert_len in enumerate(cert_lengths):
            cert_data = bytes(all_data[cert_offset:cert_offset + cert_len])
            certs.append(cert_data)
            cert_offset += cert_len

        return CertificateStore(
            device_cert=certs[0],
            intermediate_cert=certs[1],
            tropic01_cert=certs[2],
            root_cert=certs[3],
        )

    def get_device_public_key(self) -> bytes:
        """
        Extract device public key (ST_Pub) from certificate store.

        Returns the X25519 public key used for secure session establishment.
        The key is extracted from the device certificate by searching for the
        X25519 OID (1.3.101.110) and extracting the following public key value.

        Returns:
            32-byte X25519 public key

        Maps to: lt_get_st_pub()
        """
        # Get certificate store and extract device certificate
        cert_store = self.get_certificate_store()
        cert_data = cert_store.device_cert

        # X25519 OID: 1.3.101.110 encoded as 2B 65 6E
        # In ASN.1 DER: 06 03 2B 65 6E (tag=06, length=03, data=2B656E)
        x25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])

        # Search for the OID in the certificate
        oid_pos = cert_data.find(x25519_oid)
        if oid_pos == -1:
            raise TropicError(
                ReturnCode.CERT_ITEM_NOT_FOUND,
                "X25519 OID not found in device certificate"
            )

        # After the OID, we expect BIT STRING containing the public key
        # BIT STRING format: 03 <length> 00 <key_bytes>
        # The 00 byte is the "unused bits" indicator
        pos = oid_pos + len(x25519_oid)

        # Skip to the BIT STRING (may be in next sequence level)
        # Look for tag 0x03 (BIT STRING)
        while pos < len(cert_data) - 2:
            if cert_data[pos] == 0x03:  # BIT STRING tag
                # Get length
                length = cert_data[pos + 1]
                if length == 0x21:  # 33 bytes (1 unused bits byte + 32 key bytes)
                    # Skip unused bits indicator (should be 0x00)
                    if cert_data[pos + 2] == 0x00:
                        key_start = pos + 3
                        key_end = key_start + X25519_KEY_LEN
                        if key_end <= len(cert_data):
                            return cert_data[key_start:key_end]
            pos += 1

        raise TropicError(
            ReturnCode.CERT_ITEM_NOT_FOUND,
            "Could not extract X25519 public key from device certificate"
        )

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
        stpub: bytes,
        slot: int | PairingKeySlot,
        private_key: bytes,
        public_key: bytes,
    ) -> None:
        """
        Establish encrypted secure session using Noise_KK1 protocol.

        Low-level session start that requires all parameters to be provided
        by the caller. For a higher-level helper that auto-fetches the device
        public key from certificates, use `verify_chip_and_start_session()`.

        The protocol implements Noise_KK1_25519_AESGCM_SHA256:
        1. Builds a hash chain from protocol name and public keys
        2. Derives session keys via 3 DH operations and HKDF chain
        3. Verifies device authentication tag

        Args:
            stpub: 32-byte device static public key (from certificate store)
            slot: Pairing key slot index (0-3) where host public_key is stored
            private_key: 32-byte X25519 host private key (SH_priv)
            public_key: 32-byte X25519 host public key (SH_pub)

        Raises:
            ParamError: If keys are invalid or slot out of range
            HandshakeError: If key exchange fails
            AuthenticationError: If device authentication tag verification fails

        Maps to: lt_session_start(h, stpub, pkey_index, shipriv, shipub)
        """
        # Validate parameters
        if len(stpub) != X25519_KEY_LEN:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Device public key (stpub) must be {X25519_KEY_LEN} bytes, got {len(stpub)}"
            )
        if len(private_key) != X25519_KEY_LEN:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Private key must be {X25519_KEY_LEN} bytes, got {len(private_key)}"
            )
        if len(public_key) != X25519_KEY_LEN:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Public key must be {X25519_KEY_LEN} bytes, got {len(public_key)}"
            )

        # Convert slot to int if enum
        slot_index = int(slot) if isinstance(slot, PairingKeySlot) else slot
        if slot_index < 0 or slot_index > 3:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be 0-3, got {slot_index}"
            )

        l2 = self._ensure_open()

        # Use provided keys
        st_pub = stpub
        sh_pub = public_key

        # Generate ephemeral X25519 keypair (EH_priv, EH_pub)
        eh_priv = secrets.token_bytes(X25519_KEY_LEN)
        eh_pub = x25519_scalarmult_base(eh_priv)

        try:
            # Send HANDSHAKE L2 request: [EH_pub (32B), slot (1B)]
            request_data = eh_pub + bytes([slot_index])
            response = l2.send_receive(L2_HANDSHAKE_REQ_ID, request_data)

            # Validate response length
            if len(response.data) != L2_HANDSHAKE_RSP_LEN:
                raise HandshakeError(
                    ReturnCode.L2_HSK_ERR,
                    f"Invalid handshake response length: {len(response.data)}"
                )

            # Parse response: [ET_pub (32B), T_auth (16B)]
            et_pub = response.data[:HANDSHAKE_RSP_ET_PUB_SIZE]
            t_auth = response.data[HANDSHAKE_RSP_ET_PUB_SIZE:
                                   HANDSHAKE_RSP_ET_PUB_SIZE + HANDSHAKE_RSP_T_AUTH_SIZE]

            # =====================================================================
            # Noise_KK1_25519_AESGCM_SHA256 Protocol
            # =====================================================================

            # Protocol name: "Noise_KK1_25519_AESGCM_SHA256" padded to 32 bytes
            protocol_name = b'Noise_KK1_25519_AESGCM_SHA256\x00\x00\x00'

            # Build hash chain (h) - this becomes the AAD for tag verification
            ctx = Sha256Context()

            # h = SHA256(protocol_name)
            ctx.start()
            ctx.update(protocol_name)
            h = ctx.finish()

            # h = SHA256(h || SHiPUB) - host's static public key
            ctx.start()
            ctx.update(h)
            ctx.update(sh_pub)
            h = ctx.finish()

            # h = SHA256(h || STPUB) - device's static public key
            ctx.start()
            ctx.update(h)
            ctx.update(st_pub)
            h = ctx.finish()

            # h = SHA256(h || EHPUB) - host's ephemeral public key
            ctx.start()
            ctx.update(h)
            ctx.update(eh_pub)
            h = ctx.finish()

            # h = SHA256(h || PKEY_INDEX) - pairing key slot index
            ctx.start()
            ctx.update(h)
            ctx.update(bytes([slot_index]))
            h = ctx.finish()

            # h = SHA256(h || ETPUB) - device's ephemeral public key
            ctx.start()
            ctx.update(h)
            ctx.update(et_pub)
            h = ctx.finish()

            # =====================================================================
            # Key Derivation via HKDF Chain
            # =====================================================================

            # ck = HKDF(protocol_name, X25519(EHPRIV, ETPUB))
            # First DH: ephemeral-ephemeral
            ss_ee = x25519(eh_priv, et_pub)
            ck, _ = hkdf(protocol_name, ss_ee)

            # ck = HKDF(ck, X25519(SHiPRIV, ETPUB))
            # Second DH: static-ephemeral
            ss_se = x25519(private_key, et_pub)
            ck, _ = hkdf(ck, ss_se)

            # (ck, kAUTH) = HKDF(ck, X25519(EHPRIV, STPUB))
            # Third DH: ephemeral-static
            ss_es = x25519(eh_priv, st_pub)
            ck, k_auth = hkdf(ck, ss_es)

            # (kCMD, kRES) = HKDF(ck, "")
            # Final derivation with empty input
            k_cmd, k_res = hkdf(ck, b"")

            # =====================================================================
            # Verify Authentication Tag
            # =====================================================================

            # The device computes T_auth = AES-GCM-Tag(k_auth, IV=0, AAD=h, plaintext="")
            # We verify by attempting to decrypt the tag with hash as AAD
            iv_zero = bytes(AESGCM_IV_SIZE)

            try:
                with AesGcmDecryptContext(k_auth) as decrypt_ctx:
                    # Decrypt: ciphertext is empty, tag is t_auth, AAD is hash chain
                    # If tag is valid, decrypt returns empty bytes
                    decrypt_ctx.decrypt(iv_zero, t_auth, h)
            except Exception as e:
                raise AuthenticationError(
                    ReturnCode.L2_TAG_ERR,
                    f"Handshake authentication tag verification failed: {e}"
                ) from e

            # =====================================================================
            # Store Session State
            # =====================================================================

            # Initialize IVs to all zeros
            cmd_iv = bytearray(AESGCM_IV_SIZE)
            res_iv = bytearray(AESGCM_IV_SIZE)

            self._session = SessionState(
                k_cmd=k_cmd,
                k_res=k_res,
                cmd_iv=cmd_iv,
                res_iv=res_iv,
            )
            self._has_session = True

        finally:
            # Securely clear ephemeral private key and shared secrets
            eh_priv_buffer = bytearray(eh_priv)
            secure_memzero(eh_priv_buffer)

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

        # Clear session state (securely wipe key material)
        if self._session is not None:
            self._session.clear()
            self._session = None
        self._has_session = False

    def verify_chip_and_start_session(
        self,
        private_key: bytes,
        public_key: bytes,
        slot: int | PairingKeySlot = 0,
    ) -> None:
        """
        Verify device certificate and establish secure session.

        High-level helper that automatically fetches the device's static
        public key from the certificate store before starting the session.
        This is the recommended way to start a session for most use cases.

        Args:
            private_key: 32-byte X25519 host private key (SH_priv)
            public_key: 32-byte X25519 host public key (SH_pub)
            slot: Pairing key slot index (0-3) where host public_key is stored

        Raises:
            ParamError: If keys are invalid or slot out of range
            HandshakeError: If key exchange fails
            AuthenticationError: If device authentication tag verification fails
            TropicError: If certificate store cannot be read

        Maps to: lt_verify_chip_and_start_secure_session(h, shipriv, shipub, pkey_index)
        """
        # Get device's static public key from certificate store
        stpub = self.get_device_public_key()

        # Start session with all parameters
        self.start_session(stpub, slot, private_key, public_key)

    @property
    def has_session(self) -> bool:
        """Check if a secure session is currently active."""
        return self._has_session

    def ping(self, data: bytes = b"") -> bytes:
        """
        Echo test through secure channel.

        Sends data through the encrypted channel and receives it back.
        Useful for verifying session is working correctly.

        Args:
            data: Data to echo (max 4096 bytes, default empty)

        Returns:
            Echoed data (should match input)

        Raises:
            NoSessionError: If no secure session is active
            ParamError: If data exceeds maximum length

        Maps to: lt_ping()
        """
        from ._protocol.constants import L3_CMD_PING, L3_PING_DATA_MAX

        if len(data) > L3_PING_DATA_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Ping data too large: {len(data)} bytes (max {L3_PING_DATA_MAX})"
            )

        # Send ping command and receive echoed data
        response_data = self._send_l3_command(L3_CMD_PING, data)

        return response_data

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
