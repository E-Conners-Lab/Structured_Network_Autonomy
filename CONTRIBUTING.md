# Contributing to Structured Network Autonomy

Thanks for your interest in contributing to SNA.

## Getting Started

1. Fork the repository and clone your fork
2. Create a virtual environment and install dependencies:
   ```bash
   uv venv
   uv pip install -e ".[dev]"
   ```
3. Copy `.env.example` to `.env` and set the required values
4. Run the test suite to confirm everything works:
   ```bash
   python -m pytest tests/ -v
   ```

## Development Workflow

1. Create a feature branch from `main`
2. Make your changes
3. Write tests for any new functionality
4. Run the full test suite and ensure all tests pass
5. Open a pull request against `main`

## Code Style

- Python 3.12+ with async throughout
- Ruff for linting (`ruff check src/ tests/`)
- mypy for type checking (`mypy src/`)
- All public methods should have docstrings
- Structured JSON logging via structlog — no `print()` statements
- All config via environment variables, never hardcoded

## Testing

- Tests mirror the `src/sna/` structure under `tests/`
- Use `pytest-asyncio` for async tests
- Mock external dependencies (device connections, webhooks, etc.)
- Aim for high coverage on policy engine and API routes

## Security

- Never commit secrets or credentials
- Use `yaml.safe_load()` only
- Parameterized queries via SQLAlchemy ORM
- Sanitize all API error responses — no stack traces to clients
- Report vulnerabilities privately (see SECURITY.md)
