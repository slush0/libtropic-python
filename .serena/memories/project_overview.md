# Project Overview

**libtropic-python** is a pure Python reimplementation of the [libtropic](../libtropic) C library for communicating with the TROPIC01 secure element chip (TS1302) from Tropic Square.

## Purpose
- Provide full API coverage matching the official libtropic C SDK
- Support multiple transport backends (USB dongle, native Linux SPI)
- Maintain 1:1 parity with the C library API and behavior
- Offer Pythonic interface with context managers and exceptions

## Tech Stack
- **Language**: Python 3.10+
- **Core Dependencies**:
  - `cryptography>=41.0` - Cryptographic operations
  - `pyserial>=3.5` - USB dongle support (optional)
  - `spidev>=3.6, gpiod>=2.0` - SPI support (optional, Linux only)
- **Development Tools**:
  - `pytest>=7.0` - Testing framework
  - `pytest-cov>=4.0` - Coverage reporting
  - `mypy>=1.0` - Static type checking
  - `ruff>=0.1` - Linting and formatting
- **Build System**: setuptools

## Key Design Principles
1. **1:1 C Library Parity** - API must mirror libtropic C library exactly
2. **No Feature Creep** - Only implement what exists in the C library
3. **Type Safety** - Full type hints with strict mypy checking
4. **PEP 561 Compliance** - Ship with py.typed for type checking support
