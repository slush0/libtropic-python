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
    DeviceMode,
    NoSessionError,
    PairingKeySlot,
    StartupMode,
    Tropic01,
)
from libtropic.types import (
    CertificateStore,
    ChipId,
    FirmwareVersion,
)

from ..conftest import TEST_SH0_PRIV, TEST_SH0_PUB


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
    """

    def test_session_start_abort(self, device: Tropic01) -> None:
        """Test starting and aborting a secure session."""
        # Initially no session
        assert not device.has_session

        # Start session
        device.start_session(
            private_key=TEST_SH0_PRIV,
            public_key=TEST_SH0_PUB,
            slot=PairingKeySlot.SLOT_0
        )

        # Session should be active
        assert device.has_session

        # Abort session
        device.abort_session()

        # No session again
        assert not device.has_session

    def test_session_with_integer_slot(self, device: Tropic01) -> None:
        """Test starting session with integer slot parameter."""
        device.start_session(
            private_key=TEST_SH0_PRIV,
            public_key=TEST_SH0_PUB,
            slot=0  # Integer instead of enum
        )

        assert device.has_session
        device.abort_session()

    def test_operation_without_session_fails(self, device: Tropic01) -> None:
        """Test that session-protected operations fail without session."""
        # Ensure no session
        if device.has_session:
            device.abort_session()

        # Ping requires session
        with pytest.raises(NoSessionError):
            device.ping(b"test")


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
        empty bytes if logging is disabled.
        """
        log_data = device_with_session.get_log()

        # Log should be bytes (may be empty if logging disabled)
        assert isinstance(log_data, bytes)


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
