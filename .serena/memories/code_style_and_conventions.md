# Code Style and Conventions

## Python Style
- **Python Version**: 3.10+ (target version)
- **Line Length**: 100 characters (ruff configured)
- **Formatting**: Enforced by ruff
- **Import Order**: Sorted automatically by ruff (isort-style)

## Type Hints
- **Required**: All functions must have type hints
- **Mypy Configuration**: Strict mode enabled
  - `disallow_untyped_defs = true`
  - `disallow_incomplete_defs = true`
  - `warn_return_any = true`
- **PEP 561 Compliant**: Package includes `py.typed` marker file

## Naming Conventions

### C to Python Mapping
| C (libtropic)              | Python (libtropic-python)           |
|----------------------------|-------------------------------------|
| `lt_init(h)`               | `Tropic01.open()`                   |
| `lt_session_start(...)`    | `device.start_session(...)`         |
| `lt_ecc_key_generate(...)` | `device.ecc.generate(...)`          |
| `lt_r_mem_data_read(...)`  | `device.memory.read(...)`           |
| `lt_ret_t`                 | `ReturnCode` enum + exceptions      |
| `LT_ECC_CURVE_ED25519`     | `EccCurve.ED25519`                  |

### General Rules
- **Functions/Methods**: `snake_case` (Pythonic)
- **Classes**: `PascalCase`
- **Enums**: `PascalCase` for enum classes, `UPPER_CASE` for enum values
- **Constants**: `UPPER_CASE`
- **Private/Internal**: Prefix with `_` for modules/functions not in public API

## Docstrings
- **Required**: All public classes, functions, and methods
- **Format**: Google-style docstrings
- **Content**: Include purpose, parameters, return values, and exceptions raised

Example:
```python
def start_session(self, private_key: bytes, public_key: bytes, slot: int) -> None:
    """
    Start encrypted session with TROPIC01 device.

    Args:
        private_key: Host's X25519 private key (32 bytes)
        public_key: Host's X25519 public key (32 bytes)
        slot: Pairing key slot (0-3)

    Raises:
        NoSessionError: If session establishment fails
        ParamError: If key parameters are invalid
    """
```

## Code Documentation
- **Principle**: Document the WHY, not just the WHAT
- **Requirement**: Non-trivial code blocks should have comments explaining their purpose
- **Preference**: Explicit, verbose code over clever one-liners
- **Variables**: Use descriptive names that reveal intent

## Enumerations
- Use `IntEnum` from Python's enum module
- Values must match C SDK exactly
- Include docstring mapping to C type

Example:
```python
class DeviceMode(IntEnum):
    """
    Device operating mode.
    
    Maps to lt_tr01_mode_t from C SDK.
    """
    MAINTENANCE = 0
    APPLICATION = 1
    ALARM = 2
```

## Exception Handling
- Map C return codes to Python exceptions
- Use specific exception types (not generic)
- All exceptions inherit from `TropicError` base class
- Transport errors separate from device errors

## Error Handling Pattern
```python
# Check return code and raise appropriate exception
if result != ReturnCode.OK:
    raise TropicError.from_code(result, "Operation failed")
```

## Ruff Configuration
Enabled linters:
- E: pycodestyle errors
- F: pyflakes
- W: pycodestyle warnings
- I: isort (import sorting)
- N: pep8-naming
- UP: pyupgrade
- B: flake8-bugbear

## Testing Style
- Use pytest framework
- Test function names: `test_<what>_<scenario>()`
- Docstrings for test functions explaining purpose
- Use descriptive assertion messages
- Mirror C test structure where applicable
