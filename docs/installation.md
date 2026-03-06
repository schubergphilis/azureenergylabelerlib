# Installation

## For Users

### Using uv (Preferred)

```bash
uv add azureenergylabelerlib
```

### Using pip (Legacy)

```bash
pip install azureenergylabelerlib
```

## For Developers

If you want to contribute to azureenergylabeler or run it from source, follow the development setup.

### Prerequisites

- [uv](https://docs.astral.sh/uv/) - Modern Python package manager

### Setup Development Environment

#### Fork and clone the repository:

```bash
git clone https://github.com/schubergphilis/azureenergylabelerlib.git
cd azureenergylabelerlib 
```

#### Install dependencies (including dev dependencies):

```bash
uv sync --all-extras --dev
```

#### Verify the setup:

```bash
uv run python -m unittest
```

### Development Workflow

This project follows the [Paleofuturistic Python](https://github.com/schubergphilis/paleofuturistic_python) development flow.

**Code Quality:**
```bash
# Format code
uv run ruff format

# Lint code
uv run ruff check

# Type check
uv run mypy
```

**Testing:**
```bash
# Run all tests
uv run python -m unittest

# Run specific test
uv run python -m unittest tests.test_azureenergylabelerlib.TestAzureEnergyLabelerInit.test_tenant_has_one_subscription
```

**Build:**
```bash
# Build package (to validate it works)
uv build
```

**Documentation:**
```bash
# Preview documentation locally
uv run mkdocs serve
```

## Next Steps

- [Usage Guide](usage.md) - Learn how to use azureenergylabeler 
- [API Reference](api.md) - Explore the full API
- [Contributing](contributing.md) - Contribute to the project