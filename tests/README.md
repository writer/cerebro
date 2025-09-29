# Cerebro Tests

Comprehensive test suite for Cerebro security platform.

## Structure

```
tests/
├── agents/                      # Agent system integration tests
│   ├── test_agent_integration.py  # Full integration tests (requires DB)
│   └── test_agents_api.py         # API endpoint tests
├── sdk/                         # Claude SDK integration tests
│   └── test_sdk_integration.py    # SDK component tests (no DB required)
├── integration/                 # Other integration tests
│   └── test_agent_core.py
└── README.md                    # This file
```

## Running Tests

### All Tests

```bash
# Run complete test suite
uv run pytest

# Run with coverage
uv run pytest --cov=cerebro --cov-report=html --cov-report=term
```

### Agent Tests

```bash
# SDK integration tests (no database required)
uv run python tests/sdk/test_sdk_integration.py

# Agent system tests (requires database)
uv run pytest tests/agents/test_agent_integration.py -v

# API tests (requires running server)
uv run python tests/agents/test_agents_api.py
```

### Specific Test Categories

```bash
# Unit tests only
uv run pytest tests/ -m "not integration"

# Integration tests only
uv run pytest tests/ -m integration

# Skip slow tests
uv run pytest tests/ -m "not slow"
```

## Test Categories

### Unit Tests
- Fast, isolated tests
- No external dependencies
- Mock database and API calls

### Integration Tests
- Test component interactions
- Require database connection
- May require external services

### API Tests
- Test REST API endpoints
- Require running server
- Test authentication and authorization

## Prerequisites

### For SDK Tests
- No prerequisites
- Tests SDK integration without database

### For Agent Integration Tests
```bash
# Start PostgreSQL
docker-compose up -d postgres

# Run migrations
uv run alembic upgrade head

# Set environment variables
export DATABASE_URL="postgresql://user:password@localhost:5432/cerebro"
export ANTHROPIC_API_KEY="your-key-here"
```

### For API Tests
```bash
# Start the API server
uv run uvicorn cerebro.api.main:app --reload

# In another terminal, run tests
uv run python tests/agents/test_agents_api.py
```

## Writing Tests

### Test File Naming
- Test files: `test_*.py`
- Test functions: `test_*`
- Test classes: `Test*`

### Fixtures
```python
@pytest.fixture
async def test_org():
    """Create test organization."""
    # Setup
    org = await create_org()
    yield org
    # Teardown
    await delete_org(org.id)
```

### Markers
```python
@pytest.mark.integration  # Integration test
@pytest.mark.slow        # Slow test
@pytest.mark.asyncio     # Async test
```

## Continuous Integration

Tests run automatically on:
- Pull requests
- Pushes to main branch
- Nightly builds

See `.github/workflows/` for CI configuration.

## Troubleshooting

### Database Connection Errors
```bash
# Check PostgreSQL is running
docker-compose ps

# Check connection string
echo $DATABASE_URL
```

### Import Errors
```bash
# Install dependencies
uv sync --extra dev

# Check Python path
uv run python -c "import sys; print('\n'.join(sys.path))"
```

### Test Failures
```bash
# Run with verbose output
uv run pytest tests/ -vv

# Run with debug output
uv run pytest tests/ -vv -s

# Run specific test
uv run pytest tests/agents/test_agent_integration.py::test_name -vv
```

## Related Documentation

- [Testing Plan](../docs/agents/testing-plan.md)
- [Integration Test Report](../docs/agents/integration-test-report.md)
- [API Integration](../docs/agents/API_INTEGRATION.md)