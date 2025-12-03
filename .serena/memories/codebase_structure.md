# Codebase Structure

## Directory Layout

```
libtropic-python/
├── src/libtropic/              # Main package
│   ├── __init__.py             # Public API exports
│   ├── device.py               # Tropic01 main class (lt_init, lt_session_*, etc.)
│   ├── enums.py                # Enumerations (ReturnCode, DeviceMode, EccCurve, etc.)
│   ├── exceptions.py           # Exception hierarchy
│   ├── types.py                # Data structures (ChipId, FirmwareVersion, etc.)
│   ├── counters.py             # Monotonic counters (lt_mcounter_*)
│   ├── mac_and_destroy.py      # M&D slots (lt_mac_and_destroy)
│   ├── pairing_keys.py         # Pairing keys (lt_pairing_key_*)
│   ├── firmware.py             # Firmware update (lt_mutable_fw_*)
│   ├── py.typed                # PEP 561 marker file
│   ├── transport/              # Transport backends (HAL layer)
│   │   ├── base.py             # Abstract transport interface
│   │   ├── usb_dongle.py       # USB serial (TS1302 evaluation kit)
│   │   └── spi.py              # Native Linux SPI
│   ├── crypto/                 # Cryptographic operations
│   │   ├── ecc.py              # ECC operations (lt_ecc_key_*, lt_ecdsa_*, lt_eddsa_*)
│   │   └── random.py           # Hardware RNG (lt_random_value_get)
│   ├── storage/                # Storage subsystems
│   │   ├── memory.py           # R-Memory (lt_r_mem_data_*)
│   │   └── config.py           # R/I-Config (lt_r_config_*, lt_i_config_*)
│   ├── _cal/                   # Internal crypto abstraction layer
│   └── _protocol/              # Internal protocol layer (L1/L2)
│       ├── __init__.py
│       ├── constants.py        # Protocol constants
│       ├── crc16.py            # CRC16 implementation
│       ├── l1.py               # L1 protocol layer
│       └── l2.py               # L2 protocol layer
├── tests/                      # Test suite
│   ├── __init__.py
│   ├── conftest.py             # Pytest configuration
│   ├── test_imports.py         # Basic import tests
│   ├── run_unit_tests.sh       # Unit test runner
│   ├── run_integration_tests.sh # Integration test runner
│   ├── run_irreversible_tests.sh # Hardware-modifying tests
│   ├── unit/                   # Unit tests (no hardware)
│   │   └── cal/                # CAL module tests
│   ├── functional/             # Hardware functional tests
│   └── wycheproof/             # Wycheproof crypto test vectors
├── libtropic-upstream/         # Git submodule - reference C library
├── pyproject.toml              # Project metadata and config
├── README.md                   # User documentation
├── CLAUDE.md                   # Development rules and guidelines
├── PLAN.md                     # Implementation plan
└── .gitignore

## Module Responsibilities

### Core Modules
- **device.py**: Main `Tropic01` class - device lifecycle management (open/close, sessions, reboot)
- **enums.py**: All enumerations matching C SDK types (IntEnum-based)
- **exceptions.py**: Python exception hierarchy mapping from C return codes
- **types.py**: Data structures (dataclasses/NamedTuples for C structs)

### Functional Modules
- **crypto/**: ECC key operations, signing (ECDSA/EdDSA), hardware RNG
- **storage/**: User memory, configuration registers
- **counters.py**: Monotonic counter operations
- **mac_and_destroy.py**: Secure PIN verification slots
- **pairing_keys.py**: Device pairing key management
- **firmware.py**: Firmware update operations

### Infrastructure
- **transport/**: Hardware abstraction layer for USB and SPI communication
- **_cal/**: Internal crypto abstraction layer (wraps cryptography library)
- **_protocol/**: Internal L1/L2 protocol implementation (CRC, framing, encryption)
