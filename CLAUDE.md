# CLAUDE.md

**libtropic-python**: Python reimplementation of [libtropic](libtropic-upstream/) C library for Tropic01.

## Rules

### Parity with C Library
- API mirrors libtropic C — same functions, Pythonic naming
- Tests mirror C tests — port all from `libtropic-upstream/`
- No feature creep — if not in C lib, out of scope

### Development Discipline
1. **Minimal changes** — implement ONLY what's requested, no "improvements"
2. **Scope control** — don't touch unrelated code; note issues, don't fix unless asked
3. **Readability > cleverness** — comment PURPOSE (why), use descriptive names
4. **No premature abstraction** — extract only at 3+ uses; duplicate if clearer
5. **Tests immutable** — NEVER modify tests unless asked; failing test = wrong code
6. **Propose tests separately** — list needed tests, wait for approval
7. **Concise commits** — short messages, focus on why

## Structure

```
src/libtropic/
├── device.py          # Tropic01 class (lt_init, lt_session_*)
├── enums.py           # ReturnCode, DeviceMode, etc.
├── types.py           # ChipId, CertificateStore
├── exceptions.py      # TropicError, NoSessionError
├── ecc.py             # lt_ecc_key_*, lt_ecdsa_sign, lt_eddsa_sign
├── random.py          # lt_random_value_get
├── memory.py          # lt_r_mem_data_*
├── config.py          # lt_r_config_*, lt_i_config_*
├── counters.py        # lt_mcounter_*
├── mac_and_destroy.py # lt_mac_and_destroy
├── pairing_keys.py    # lt_pairing_key_*
├── keys.py            # Key slots
├── firmware.py        # lt_mutable_fw_*
├── _cal/              # Crypto primitives (aesgcm, hkdf, x25519, sha256, hmac)
├── _protocol/         # L1/L2/L3 layers, CRC16
└── transport/         # HAL: base.py, usb_dongle.py, spi.py
```

## Naming

| C                        | Python                      |
|--------------------------|-----------------------------|
| `lt_init(h)`             | `Tropic01.open()`           |
| `lt_session_start()`     | `device.start_session()`    |
| `lt_ecc_key_generate()`  | `device.ecc.generate()`     |
| `lt_r_mem_data_read()`   | `device.memory.read()`      |
| `lt_ret_t`               | `ReturnCode` + exceptions   |

## Dev Setup

```bash
source .venv/bin/activate
```

Tests: `lt_test_rev_*.c` → `tests/test_*.py`
