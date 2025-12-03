# libtropic-python

Python SDK for the TROPIC01 secure element from [Tropic Square](https://tropicsquare.com).


 >[!WARNING]
 > This is a community-driven project. The code is not officially supported or maintained by Tropic Square.
 > Tropic Square is not responsible for this code. Do not use it for production unless you know what you are doing.

## ⚠️ Disclaimers

- **SPI interface has not been tested** — the native Linux SPI transport is implemented but remains untested on real hardware.
- **Limited test coverage** — not all test scenarios have been verified because the developer currently does not have access to a vanilla devkit device.

## Features

- Full API coverage matching the official libtropic C SDK
- Multiple transport backends (USB dongle, native Linux SPI)
- Type hints and PEP 561 compliance
- Pythonic interface with context managers and exceptions

## Installation

```bash
# Basic installation
pip install libtropic

# With USB dongle support (pyserial)
pip install libtropic[usb]

# With native SPI support (Linux only)
pip install libtropic[spi]

# All transports
pip install libtropic[all]
```

## Quick Start

### USB Dongle (TS1302 Evaluation Kit)

```python
from libtropic import Tropic01, EccCurve
from libtropic.keys import (
    # For production TROPIC01 chips (most devices)
    SH0_PRIV_PROD, SH0_PUB_PROD,
    # For engineering sample TROPIC01-ES chips (pre-production)
    SH0_PRIV_ENG_SAMPLE, SH0_PUB_ENG_SAMPLE,
)

with Tropic01("/dev/ttyACM0") as device:
    # Check device mode
    print(f"Device mode: {device.mode.name}")

    # Verify chip certificate and start secure session
    # Use SH0_*_PROD keys for production chips (default)
    # Use SH0_*_ENG_SAMPLE keys for engineering sample chips (TROPIC01-ES)
    device.verify_chip_and_start_session(
        private_key=SH0_PRIV_PROD,
        public_key=SH0_PUB_PROD,
        slot=0,
    )

    # Generate ECC key
    device.ecc.generate(slot=0, curve=EccCurve.ED25519)

    # Sign a message
    signature = device.ecc.sign_eddsa(slot=0, message=b"Hello, TROPIC01!")

    # Get random bytes
    random_data = device.random.get_bytes(32)
```

### Native SPI (Raspberry Pi, BeagleBone, etc.)

```python
from libtropic import connect_spi
from libtropic.keys import SH0_PRIV_PROD, SH0_PUB_PROD

with connect_spi(
    spi_device="/dev/spidev0.0",
    gpio_chip="/dev/gpiochip0",
    cs_pin=8,
    int_pin=25  # optional
) as device:
    device.verify_chip_and_start_session(
        private_key=SH0_PRIV_PROD,
        public_key=SH0_PUB_PROD,
        slot=0,
    )
    # ... use device
```

## API Overview

### Main Device Class

```python
from libtropic import Tropic01

device = Tropic01(transport)
device.open()                              # Initialize (or use context manager)
device.mode                                # Get current mode (MAINTENANCE/APPLICATION/ALARM)
device.verify_chip_and_start_session(...)  # Verify chip and start encrypted session
device.abort_session()                     # End session
device.reboot(mode)                        # Reboot device
device.close()                             # Cleanup
```

### Sub-modules

| Module | Description |
|--------|-------------|
| `device.ecc` | ECC key operations (32 slots, P256/Ed25519) |
| `device.random` | Hardware random number generator |
| `device.memory` | User data storage (512 slots) |
| `device.config` | R-Config and I-Config access |
| `device.counters` | Monotonic counters (16 counters) |
| `device.mac_and_destroy` | Secure PIN verification (128 slots) |
| `device.pairing_keys` | Pairing key management (4 slots) |
| `device.firmware` | Firmware update (maintenance mode) |

### Exceptions

All operations raise specific exceptions on failure:

```python
from libtropic import (
    TropicError,          # Base exception
    NoSessionError,       # Operation requires active session
    ParamError,           # Invalid parameter
    SlotEmptyError,       # Accessing empty slot
    UnauthorizedError,    # Insufficient privileges
    # ... and more
)
```

## Development

```bash
# Clone repository
git clone https://github.com/tropicsquare/libtropic-python.git
cd libtropic-python

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy src/libtropic

# Linting
ruff check src tests
```

## Project Structure

```
libtropic-python/
├── src/
│   └── libtropic/           # Main package
│       ├── __init__.py      # Public API exports
│       ├── device.py        # Tropic01 main class
│       ├── enums.py         # Enumerations
│       ├── exceptions.py    # Exception hierarchy
│       ├── types.py         # Data types
│       ├── transport/       # Transport backends
│       ├── crypto/          # ECC and RNG operations
│       └── storage/         # Memory and config
├── tests/                   # Test suite
├── pyproject.toml           # Project metadata
└── README.md
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- [TROPIC01 Product Page](https://tropicsquare.com/tropic01)
- [libtropic C SDK](https://github.com/tropicsquare/libtropic)
- [Tropic Square](https://tropicsquare.com)
