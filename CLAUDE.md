# CLAUDE.md

## Project Overview

**libtropic-python**: Pure Python reimplementation of [libtropic](../libtropic) C library for communicating with Tropic01 secure element chip (TS1302).

## 🎯 PROJECT-SPECIFIC RULES

### 1:1 C Library Parity
- **API must mirror libtropic C library** — same functions, same behavior, Pythonic naming conventions.
- **Test coverage must mirror libtropic C tests** — port all C unit tests to Python equivalents.
- **No feature creep** — if it doesn't exist in libtropic C, don't implement it here. Out of scope.

Reference: `../libtropic/` for API and test specifications.

---

## ⚠️ CRITICAL DEVELOPMENT RULES

### 1. Minimal Change Principle
- **NEVER implement more functionality than explicitly requested by the user.**
- If the user asks for a bug fix, fix only that bug. Do not "improve" surrounding code.
- If the user asks for a feature, implement only that feature. Do not add "nice-to-have" extras.
- Resist the urge to refactor, optimize, or enhance code that wasn't mentioned in the request.

### 2. Scope Discipline
- **NEVER change or refactor code which is not directly related to the change requested by user.**
- Before modifying any function, ask: "Is this function directly involved in what the user requested?"
- If you find unrelated issues while working, note them but do not fix them unless asked.
- Keep pull requests focused and reviewable.

### 3. Code Readability Over Cleverness
- **Keep the source code with well-documented intentions of code blocks.**
- Every non-trivial code block should have a comment explaining its PURPOSE (why), not just its mechanism (what).
- Prefer explicit, verbose code over clever one-liners that require mental parsing.
- Use descriptive variable names that reveal intent.

### 4. Avoid Premature Abstraction
- **Avoid duplicating code, but NOT at the cost of branching and limiting readability by the human.**
- Code that is similar but serves different purposes may be intentionally duplicated for clarity.
- Do not create abstractions for code that is only used once or twice.
- If abstraction adds indirection that makes debugging harder, keep the code inline.
- The threshold for extracting a function: 3+ uses AND the abstraction genuinely improves understanding.

### 5. Tests Are Immutable Guards
- **NEVER modify tests unless explicitly requested by user.**
- Tests exist to detect breaking changes in the codebase—they must remain stable.
- If tests fail after your changes, the code is wrong, not the tests.

### 6. Propose Test Coverage Separately
- **After implementing a feature or change, propose test updates and ask user for approval.**
- List what new tests or modifications would be needed.
- Wait for explicit user confirmation before touching any test files.

### 7. Concise Git Commits
- **Keep commit messages short—use bullet points if needed.**
- Focus on why, less on what and how.

---

## Development Overview

### Structure

```
src/libtropic/
├── device.py         # Main Tropic01 class (maps to lt_init, lt_deinit, lt_session_*, etc.)
├── enums.py          # All enums (lt_ret_t → ReturnCode, lt_tr01_mode_t → DeviceMode, etc.)
├── types.py          # Data structures (lt_chip_id_t → ChipId, lt_cert_store_t → CertificateStore)
├── exceptions.py     # Error mapping (LT_FAIL → TropicError, LT_HOST_NO_SESSION → NoSessionError)
├── crypto/
│   ├── ecc.py        # ECC operations (lt_ecc_key_*, lt_ecdsa_sign, lt_eddsa_sign)
│   └── random.py     # RNG (lt_random_value_get)
├── storage/
│   ├── memory.py     # R-Memory (lt_r_mem_data_*)
│   └── config.py     # R/I-Config (lt_r_config_*, lt_i_config_*)
├── counters.py       # Monotonic counters (lt_mcounter_*)
├── mac_and_destroy.py # M&D slots (lt_mac_and_destroy)
├── pairing_keys.py   # Pairing keys (lt_pairing_key_*)
├── firmware.py       # FW update (lt_mutable_fw_*)
└── transport/        # HAL layer (maps to hal/posix/usb_dongle, hal/linux/spi)
    ├── base.py       # Abstract transport
    ├── usb_dongle.py # USB serial (TS1302)
    └── spi.py        # Native Linux SPI
```

### API Naming Convention

| C (libtropic)              | Python (libtropic-python)           |
|----------------------------|-------------------------------------|
| `lt_init(h)`               | `Tropic01.open()`                   |
| `lt_session_start(...)`    | `device.start_session(...)`         |
| `lt_ecc_key_generate(...)` | `device.ecc.generate(...)`          |
| `lt_r_mem_data_read(...)`  | `device.memory.read(...)`           |
| `lt_ret_t`                 | `ReturnCode` enum + exceptions      |

### Test Parity

Port C functional tests from `../libtropic/tests/functional/`:
- `lt_test_rev_*.c` → `tests/test_*.py`
- Each C test function → equivalent pytest function
- Same test scenarios, Pythonic assertions

---
