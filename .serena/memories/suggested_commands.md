# Suggested Development Commands

## Installation and Setup

```bash
# Clone repository (if needed)
git clone https://github.com/tropicsquare/libtropic-python.git
cd libtropic-python

# Install in development mode with all dependencies
pip install -e ".[dev]"

# Install with specific transport support
pip install -e ".[usb]"     # USB dongle only
pip install -e ".[spi]"     # SPI only
pip install -e ".[all]"     # All transports
```

## Testing

```bash
# Run all unit tests (no hardware required)
pytest tests/unit/ tests/test_imports.py

# Or use the shell script
./tests/run_unit_tests.sh

# Run with coverage
pytest --cov=src/libtropic tests/

# Run specific test file
pytest tests/test_imports.py -v

# Run specific test function
pytest tests/test_imports.py::test_import_main_module -v

# Run integration tests (requires hardware)
./tests/run_integration_tests.sh

# Run irreversible tests (WARNING: modifies hardware)
./tests/run_irreversible_tests.sh
```

## Code Quality

```bash
# Type checking with mypy
mypy src/libtropic

# Linting with ruff
ruff check src tests

# Auto-fix linting issues
ruff check --fix src tests

# Format code (if ruff formatter is used)
ruff format src tests
```

## Git Commands

```bash
# Check status
git status

# Stage changes
git add <file>

# Commit changes
git commit -m "Brief description"

# View commit history
git log --oneline

# View differences
git diff
git diff --staged

# Update submodule (libtropic-upstream)
git submodule update --init --recursive
```

## Development Workflow

```bash
# 1. Install dependencies
pip install -e ".[dev]"

# 2. Make changes to code
# ... edit files ...

# 3. Run type checking
mypy src/libtropic

# 4. Run linting
ruff check src tests

# 5. Run tests
pytest

# 6. Check coverage
pytest --cov=src/libtropic --cov-report=term-missing
```

## Python Virtual Environment

```bash
# Create virtual environment
python -m venv .venv

# Activate (Linux/macOS)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate

# Deactivate
deactivate
```

## File Operations (Linux)

```bash
# List directory contents
ls -la

# Change directory
cd <path>

# Find files
find . -name "*.py"

# Search in files
grep -r "pattern" src/

# View file contents
cat <file>
less <file>

# Show directory tree
tree -L 3 src/
```

## System Information

```bash
# Python version
python --version

# Installed packages
pip list
pip show libtropic

# System info
uname -a
```
