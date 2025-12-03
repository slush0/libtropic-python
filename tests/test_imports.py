"""Basic import tests for libtropic package."""



def test_import_main_module():
    """Test that main module can be imported."""
    import libtropic
    assert hasattr(libtropic, "__version__")
    assert hasattr(libtropic, "Tropic01")


def test_import_enums():
    """Test that enums can be imported."""
    from libtropic import (
        DeviceMode,
        EccCurve,
        StartupMode,
    )

    assert DeviceMode.APPLICATION == 1
    assert EccCurve.ED25519 == 2
    assert StartupMode.REBOOT == 0x01


def test_import_exceptions():
    """Test that exceptions can be imported."""
    from libtropic import (
        NoSessionError,
        SlotEmptyError,
        TropicError,
    )

    assert issubclass(NoSessionError, TropicError)
    assert issubclass(SlotEmptyError, TropicError)


def test_import_types():
    """Test that data types can be imported."""
    from libtropic import (
        FirmwareVersion,
    )

    # Test FirmwareVersion can be instantiated
    ver = FirmwareVersion(major=1, minor=2, patch=3)
    assert str(ver) == "1.2.3"


def test_import_transport():
    """Test that transport classes can be imported."""
    from libtropic import (
        SpiConfig,
    )

    config = SpiConfig()
    assert config.spi_device == "/dev/spidev0.0"


def test_import_factory_functions():
    """Test that factory functions can be imported."""
    from libtropic import connect_spi, connect_usb_dongle

    assert callable(connect_usb_dongle)
    assert callable(connect_spi)


def test_device_instantiation():
    """Test that Tropic01 can be instantiated without connection."""
    from libtropic import Tropic01

    device = Tropic01("/dev/ttyACM0")
    assert repr(device) == "<Tropic01 closed, no session>"


def test_device_submodules():
    """Test that device submodules are accessible."""
    from libtropic import Tropic01

    device = Tropic01("/dev/ttyACM0")

    # Check lazy-loaded submodules exist
    assert device.ecc is not None
    assert device.random is not None
    assert device.memory is not None
    assert device.config is not None
    assert device.counters is not None
    assert device.mac_and_destroy is not None
    assert device.pairing_keys is not None
    assert device.firmware is not None

