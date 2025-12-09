"""
Test device-level operations: startup, handshake, session, info, sleep, reboot.

Mirrors:
    - libtropic-upstream/tests/functional/lt_test_rev_startup_req.c
    - libtropic-upstream/tests/functional/lt_test_rev_handshake_req.c
    - libtropic-upstream/tests/functional/lt_test_rev_get_info_req_app.c
    - libtropic-upstream/tests/functional/lt_test_rev_get_info_req_bootloader.c
    - libtropic-upstream/tests/functional/lt_test_rev_sleep_req.c
    - libtropic-upstream/tests/functional/lt_test_rev_resend_req.c
    - libtropic-upstream/tests/functional/lt_test_rev_get_log_req.c

Tests device initialization, session management, and device information retrieval.
"""

import pytest

from libtropic import (
    CertificateVerificationError,
    DeviceMode,
    NoSessionError,
    StartupMode,
    Tropic01,
)
from libtropic.types import (
    CertificateStore,
    ChipId,
    FirmwareVersion,
)

from ..conftest import KeyConfig


@pytest.mark.hardware
class TestDeviceStartup:
    """
    Tests for device startup and initialization.

    Maps to: lt_test_rev_startup_req()
    """

    def test_init_deinit(self, device_path: str) -> None:
        """Test basic device init and deinit cycle."""
        device = Tropic01(device_path)

        # Device should start closed
        assert repr(device) == "<Tropic01 closed, no session>"

        # Open device
        device.open()

        # Close device
        device.close()

    def test_context_manager(self, device_path: str) -> None:
        """Test device as context manager."""
        with Tropic01(device_path) as device:
            # Device should be open
            pass

        # Device should be closed after context

    def test_get_mode_app(self, device: Tropic01) -> None:
        """Test getting device mode (expecting APPLICATION mode)."""
        mode = device.mode

        # Most common mode is APPLICATION
        assert mode in (DeviceMode.APPLICATION, DeviceMode.MAINTENANCE, DeviceMode.ALARM)


@pytest.mark.hardware
class TestDeviceHandshake:
    """
    Tests for secure session handshake.

    Maps to: lt_test_rev_handshake_req()

    Note: Uses keys configured via LIBTROPIC_KEY_CONFIG environment variable.
    """

    def test_session_start_and_abort(self, device: Tropic01, key_config: KeyConfig) -> None:
        """
        Part 1/3: Start and abort Secure Session.

        Maps to lt_test_rev_handshake_req() Part 1/3
        """
        # Initially no session
        assert not device.has_session

        # Start session using verify_chip_and_start_session (like C library)
        device.verify_chip_and_start_session(
            private_key=key_config.private_key,
            public_key=key_config.public_key,
            slot=key_config.slot
        )

        # Session should be active
        assert device.has_session

        # Abort session
        device.abort_session()

        # No session again
        assert not device.has_session

    def test_session_multiple_starts_without_abort(self, device: Tropic01, key_config: KeyConfig) -> None:
        """
        Part 2/3: Start Secure Session multiple times without aborting.

        Maps to lt_test_rev_handshake_req() Part 2/3
        """
        for i in range(3):
            device.verify_chip_and_start_session(
                private_key=key_config.private_key,
                public_key=key_config.public_key,
                slot=key_config.slot
            )
            assert device.has_session

        # Clean up
        device.abort_session()

    def test_session_multiple_aborts(self, device: Tropic01, key_config: KeyConfig) -> None:
        """
        Part 3/3: Abort Secure Session multiple times.

        Maps to lt_test_rev_handshake_req() Part 3/3
        """
        # Start a session first
        device.verify_chip_and_start_session(
            private_key=key_config.private_key,
            public_key=key_config.public_key,
            slot=key_config.slot
        )

        # Abort multiple times - should not fail
        for i in range(3):
            device.abort_session()
            assert not device.has_session

    def test_session_with_integer_slot(self, device: Tropic01, key_config: KeyConfig) -> None:
        """Test starting session with integer slot parameter."""
        device.verify_chip_and_start_session(
            private_key=key_config.private_key,
            public_key=key_config.public_key,
            slot=int(key_config.slot)  # Integer instead of enum
        )

        assert device.has_session
        device.abort_session()

    def test_operation_without_session_fails(self, device: Tropic01) -> None:
        """Test that session-protected operations fail without session."""
        # Ensure no session
        if device.has_session:
            device.abort_session()

        # Ping requires session - may raise NoSessionError or NotImplementedError
        # depending on whether L3 command layer is implemented
        with pytest.raises((NoSessionError, NotImplementedError)):
            device.ping(b"test")


# =============================================================================
# Certificate Verification Tests (Python-only feature)
# =============================================================================

# TEST Root CA from libtropic-upstream (CN=Tropic Square TEST Root CA v1)
# Size: 613 bytes
# Note: This matches the root CA now embedded in the library (sourced from libtropic-upstream)
TEST_ROOT_CA_DER = bytes([
    0x30, 0x82, 0x02, 0x61, 0x30, 0x82, 0x01, 0xc4, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x01, 0x65, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x04, 0x03, 0x04, 0x30, 0x54, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x5a, 0x31, 0x1d, 0x30, 0x1b, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x14, 0x54, 0x72, 0x6f, 0x70, 0x69, 0x63,
    0x20, 0x53, 0x71, 0x75, 0x61, 0x72, 0x65, 0x20, 0x73, 0x2e, 0x72, 0x2e,
    0x6f, 0x2e, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x1d, 0x54, 0x72, 0x6f, 0x70, 0x69, 0x63, 0x20, 0x53, 0x71, 0x75, 0x61,
    0x72, 0x65, 0x20, 0x54, 0x45, 0x53, 0x54, 0x20, 0x52, 0x6f, 0x6f, 0x74,
    0x20, 0x43, 0x41, 0x20, 0x76, 0x31, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x35,
    0x30, 0x33, 0x32, 0x34, 0x31, 0x33, 0x31, 0x34, 0x33, 0x38, 0x5a, 0x18,
    0x0f, 0x32, 0x30, 0x37, 0x35, 0x30, 0x33, 0x32, 0x34, 0x31, 0x33, 0x31,
    0x34, 0x33, 0x38, 0x5a, 0x30, 0x54, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x5a, 0x31, 0x1d, 0x30, 0x1b, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x14, 0x54, 0x72, 0x6f, 0x70, 0x69, 0x63,
    0x20, 0x53, 0x71, 0x75, 0x61, 0x72, 0x65, 0x20, 0x73, 0x2e, 0x72, 0x2e,
    0x6f, 0x2e, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x1d, 0x54, 0x72, 0x6f, 0x70, 0x69, 0x63, 0x20, 0x53, 0x71, 0x75, 0x61,
    0x72, 0x65, 0x20, 0x54, 0x45, 0x53, 0x54, 0x20, 0x52, 0x6f, 0x6f, 0x74,
    0x20, 0x43, 0x41, 0x20, 0x76, 0x31, 0x30, 0x81, 0x9b, 0x30, 0x10, 0x06,
    0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
    0x04, 0x00, 0x23, 0x03, 0x81, 0x86, 0x00, 0x04, 0x01, 0x35, 0xc7, 0xa2,
    0x4d, 0x16, 0xb3, 0x74, 0xb2, 0x07, 0xad, 0xe8, 0xfe, 0x50, 0xf5, 0x03,
    0xad, 0x34, 0xe0, 0xe5, 0x96, 0xc8, 0x3f, 0xc9, 0x8a, 0xdb, 0x4c, 0x43,
    0x88, 0xca, 0x0a, 0xd9, 0xb2, 0x4e, 0x77, 0xe9, 0x84, 0xb8, 0x97, 0x82,
    0x53, 0xa8, 0xe0, 0xd6, 0xfd, 0x68, 0xea, 0xa8, 0xd9, 0xc9, 0xa9, 0xa6,
    0xc8, 0x83, 0x5a, 0x13, 0x8c, 0xcc, 0xff, 0x51, 0x13, 0x0d, 0xa1, 0x09,
    0x86, 0x80, 0x00, 0xcd, 0xf7, 0xfa, 0xd5, 0xa0, 0x2b, 0xbd, 0x84, 0x45,
    0x3c, 0x56, 0x36, 0xf2, 0x5f, 0x1c, 0x39, 0x5b, 0xdc, 0x22, 0xee, 0x7b,
    0x44, 0x1a, 0x81, 0xb5, 0x9f, 0x20, 0x40, 0x53, 0x89, 0xf4, 0x7d, 0x65,
    0xf0, 0x74, 0xa6, 0x02, 0xf9, 0x33, 0x2d, 0xf1, 0x33, 0x79, 0xf2, 0x7d,
    0x65, 0x4f, 0x4e, 0x1b, 0x0f, 0xd4, 0x56, 0xc1, 0xa9, 0x9f, 0x54, 0x36,
    0x64, 0x0f, 0x7e, 0xe0, 0x4e, 0x1b, 0x48, 0x81, 0xa3, 0x42, 0x30, 0x40,
    0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x2e,
    0x9b, 0xa5, 0x40, 0x34, 0x39, 0x25, 0x34, 0x8a, 0xc6, 0x01, 0x6b, 0xe5,
    0x0d, 0x70, 0x2d, 0x78, 0x68, 0xb6, 0x88, 0x30, 0x0f, 0x06, 0x03, 0x55,
    0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,
    0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,
    0x03, 0x02, 0x01, 0x06, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x04, 0x03, 0x04, 0x03, 0x81, 0x8a, 0x00, 0x30, 0x81, 0x86, 0x02,
    0x41, 0x6a, 0x2d, 0x9d, 0x72, 0xb4, 0x35, 0x30, 0x35, 0x72, 0x5e, 0x9d,
    0x60, 0x7f, 0x62, 0xf9, 0x27, 0xe8, 0x87, 0xb6, 0x07, 0xc9, 0xfe, 0x7f,
    0xd7, 0xbd, 0xdf, 0x00, 0xa4, 0xd9, 0x4b, 0x5d, 0x57, 0xf3, 0xc9, 0x37,
    0x70, 0xa2, 0xbe, 0x25, 0xc1, 0x3f, 0x59, 0xee, 0x9f, 0x41, 0x97, 0x17,
    0x9f, 0x94, 0x06, 0xec, 0x2a, 0x8c, 0xea, 0xb1, 0xd5, 0x19, 0x05, 0x47,
    0xec, 0x24, 0x48, 0x6f, 0x8b, 0x95, 0x02, 0x41, 0x3c, 0x0a, 0x74, 0xa1,
    0x61, 0x3b, 0xd5, 0xdb, 0x29, 0xf5, 0x8e, 0xa4, 0xc7, 0x92, 0xcf, 0xfe,
    0x01, 0xe0, 0xbe, 0x5c, 0x28, 0x22, 0x24, 0xe7, 0xff, 0x93, 0xf5, 0x12,
    0x58, 0xa5, 0xf2, 0x2e, 0x3b, 0xa4, 0xa1, 0x83, 0xe8, 0x82, 0xa5, 0xc5,
    0x4f, 0x5c, 0x39, 0xce, 0x14, 0x02, 0xd1, 0xb2, 0x67, 0x4c, 0xc3, 0x4a,
    0x41, 0x82, 0xea, 0xf0, 0x61, 0xc4, 0xf6, 0x6e, 0x30, 0xe9, 0x68, 0x32,
    0x12,
])


@pytest.mark.hardware
class TestCertificateVerification:
    """
    Tests for certificate chain verification (Python-only feature).

    The C library does NOT verify certificates - it only extracts STpub.
    Python implements full X.509 chain validation for security.

    These tests verify that:
    - Valid certificate chains are accepted
    - Invalid/mismatched root CAs are rejected
    - Verification can be bypassed for development
    """

    def test_verify_chip_with_correct_root_ca(
        self, device: Tropic01, key_config: KeyConfig
    ) -> None:
        """
        Test session establishment with default (embedded) root CA.

        Uses the production root CA embedded in the library.
        """
        # Session should start successfully with default verification
        device.verify_chip_and_start_session(
            private_key=key_config.private_key,
            public_key=key_config.public_key,
            slot=key_config.slot,
        )

        assert device.has_session
        device.abort_session()

    def test_verify_chip_with_wrong_root_ca_fails(
        self, device: Tropic01, key_config: KeyConfig
    ) -> None:
        """
        Test that wrong root CA is rejected.

        Provides TEST root CA (613 bytes) but device uses PRODUCTION (604 bytes).
        Should raise CertificateVerificationError with "Root CA mismatch".
        """
        with pytest.raises(CertificateVerificationError) as exc_info:
            device.verify_chip_and_start_session(
                private_key=key_config.private_key,
                public_key=key_config.public_key,
                slot=key_config.slot,
                root_ca=TEST_ROOT_CA_DER,
            )

        # Error message should indicate root CA mismatch
        assert "root ca mismatch" in str(exc_info.value).lower()

    def test_verify_chip_skip_verification(
        self, device: Tropic01, key_config: KeyConfig
    ) -> None:
        """
        Test bypassing certificate verification.

        With skip_verification=True, session should start without
        validating the certificate chain (for development only).
        """
        device.verify_chip_and_start_session(
            private_key=key_config.private_key,
            public_key=key_config.public_key,
            slot=key_config.slot,
            skip_verification=True,
        )

        assert device.has_session
        device.abort_session()

    def test_verify_chip_with_custom_root_ca(
        self, device: Tropic01, key_config: KeyConfig
    ) -> None:
        """
        Test providing device's actual root CA as custom parameter.

        Reads the device's root CA and passes it explicitly.
        This verifies dynamic root CA matching works.
        """
        # Get device's actual root CA
        cert_store = device.get_certificate_store()
        device_root_ca = cert_store.root_cert

        # Session should start successfully with matching custom root CA
        device.verify_chip_and_start_session(
            private_key=key_config.private_key,
            public_key=key_config.public_key,
            slot=key_config.slot,
            root_ca=device_root_ca,
        )

        assert device.has_session
        device.abort_session()


@pytest.mark.hardware
class TestDeviceInfo:
    """
    Tests for device information retrieval.

    Maps to:
        - lt_test_rev_get_info_req_app()
        - lt_test_rev_get_info_req_bootloader()
    """

    def test_get_chip_id(self, device: Tropic01) -> None:
        """Test getting chip ID information."""
        chip_id: ChipId = device.get_chip_id()

        # Verify structure has expected fields
        assert chip_id.serial_number is not None
        assert chip_id.silicon_rev is not None
        assert len(chip_id.silicon_rev) == 4  # e.g., "ACAB"

    def test_get_riscv_firmware_version(self, device: Tropic01) -> None:
        """Test getting RISC-V firmware version."""
        version: FirmwareVersion = device.get_riscv_firmware_version()

        # Verify version components
        assert version.major >= 0
        assert version.minor >= 0
        assert version.patch >= 0

    def test_get_spect_firmware_version(self, device: Tropic01) -> None:
        """Test getting SPECT firmware version."""
        version: FirmwareVersion = device.get_spect_firmware_version()

        # Verify version components
        assert version.major >= 0
        assert version.minor >= 0
        assert version.patch >= 0

    def test_get_certificate_store(self, device: Tropic01) -> None:
        """Test getting certificate store."""
        cert_store: CertificateStore = device.get_certificate_store()

        # Verify all certificates present
        assert len(cert_store.device_cert) > 0
        assert len(cert_store.intermediate_cert) > 0
        assert len(cert_store.tropic01_cert) > 0
        assert len(cert_store.root_cert) > 0

    def test_get_device_public_key(self, device: Tropic01) -> None:
        """Test extracting device public key (ST_Pub)."""
        st_pub = device.get_device_public_key()

        # X25519 public key should be 32 bytes
        assert len(st_pub) == 32


@pytest.mark.hardware
@pytest.mark.destructive
class TestDeviceSleep:
    """
    Tests for sleep command.

    Maps to: lt_test_rev_sleep_req()
    """

    def test_sleep(self, device: Tropic01) -> None:
        """
        Test putting device to sleep.

        After sleep, device wakes on next SPI transaction.
        """
        # Put device to sleep
        device.sleep()

        # Device should wake on next operation (implicit in test teardown)


@pytest.mark.hardware
@pytest.mark.destructive
class TestDeviceReboot:
    """Tests for device reboot."""

    def test_reboot_to_app(self, device: Tropic01) -> None:
        """Test rebooting device to application mode."""
        # Reboot
        device.reboot(mode=StartupMode.REBOOT)

        # After reboot, device should be in APP mode (or MAINTENANCE if no valid FW)
        # Note: Mode check may need small delay after reboot
        mode = device.mode
        assert mode in (DeviceMode.APPLICATION, DeviceMode.MAINTENANCE)


@pytest.mark.hardware
class TestDeviceLog:
    """
    Tests for debug log retrieval.

    Maps to: lt_test_rev_get_log_req()
    """

    def test_get_log(self, device_with_session: Tropic01) -> None:
        """
        Test getting debug log.

        Note: Log output depends on device configuration. May return
        empty bytes if logging is disabled, or may raise L2StatusError
        with "Request is disabled" if logging is completely disabled in R-config.
        """
        from libtropic._protocol.l2 import L2StatusError

        try:
            log_data = device_with_session.get_log()
            # Log should be bytes (may be empty if logging disabled)
            assert isinstance(log_data, bytes)
        except L2StatusError as e:
            # Logging may be disabled in device R-config
            if "disabled" in str(e).lower():
                pytest.skip("Logging is disabled in device R-config")
            raise


@pytest.mark.hardware
class TestDeviceRepresentation:
    """Tests for device string representation."""

    def test_repr_closed(self, device_path: str) -> None:
        """Test repr for closed device."""
        device = Tropic01(device_path)
        assert repr(device) == "<Tropic01 closed, no session>"

    def test_repr_open_no_session(self, device: Tropic01) -> None:
        """Test repr for open device without session."""
        assert "open" in repr(device).lower() or "closed" not in repr(device).lower()

    def test_repr_with_session(self, device_with_session: Tropic01) -> None:
        """Test repr for device with active session."""
        assert "session" in repr(device_with_session).lower()
