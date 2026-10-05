# Contributing to File Integrity Monitor

We welcome contributions to the File Integrity Monitoring system!

## Development Guidelines

1. **Python Standards:** Python 3.12+, strict type hints, PEP 8 compliance.
2. **Quality Gates:** All code must pass:
   - `pytest --cov=fim tests/` (minimum 90% statement coverage)
   - `ruff check .`
   - `ruff format --check .`
   - `mypy src/ tests/`
   - `bandit -r src/ -c pyproject.toml`
3. **Defensive Coding:**
   - Always resolve symlinks safely (`pathlib.Path.resolve()`).
   - Use streaming chunked hashing for files to prevent out-of-memory errors on large targets.
   - Never print or leak raw file contents into alert payloads.
