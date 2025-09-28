# Cerebro Agent Instructions

This document provides context for AI agents working on the Cerebro Security System of Record.

## Frequently Used Commands

### Development
- **Start API server**: `uvicorn cerebro.api.main:app --reload`
- **Run CLI**: `python -m cerebro.cli`
- **Run tests**: `pytest`
- **Type checking**: `mypy src/`
- **Code formatting**: `black . && isort .`
- **Linting**: `flake8 src/`

### Database
- **Run migrations**: `alembic upgrade head`
- **Create migration**: `alembic revision --autogenerate -m "description"`
- **Reset database**: `alembic downgrade base && alembic upgrade head`

### CLI Operations
- **Create organization**: `python -m cerebro.cli org create --name "Company Name"`
- **List rules**: `python -m cerebro.cli rules list`
- **Collect data**: `python -m cerebro.cli collect "Company Name" --provider github aws`
- **Generate findings**: `python -m cerebro.cli findings generate --org-name "Company Name"`

## Project Structure

```
cerebro/
├── src/cerebro/           # Main package
│   ├── api/              # FastAPI application
│   ├── cli/              # Command-line interface  
│   ├── collectors/       # Configuration collectors
│   ├── core/             # Core models & database
│   ├── findings/         # Finding management
│   ├── providers/        # Provider integrations
│   └── rules/            # CEL rule engine
├── migrations/           # Database migrations
├── tests/               # Test suite
└── scripts/             # Utility scripts
```

## Code Style & Conventions

### Python Style
- Use **Black** for formatting (line length: 88)
- Use **isort** for import sorting
- Follow **PEP 8** naming conventions
- Add **type hints** for all functions
- Use **docstrings** for modules, classes, and functions

### File Organization
- **One class per file** - Each producer, provider, or service gets its own file
- **Descriptive file names** - Use snake_case matching the class name
- **Provider separation** - Organize by provider: `findings/producers/github/`, `providers/aws/`
- **No "god files"** - Split large files by responsibility (max 200 lines per file)
- **Auto-discovery** - Use registry pattern with `@register_provider` decorators

### Database
- All UUIDs use `UUID` type with `gen_random_uuid()` default
- Timestamps use `DateTime(timezone=True)` 
- Append-only tables: `config_snapshots`, `iam_edges`, `audit_events`
- Use foreign key constraints with appropriate `ON DELETE` actions

### API Design
- REST endpoints follow `/api/v1/resource` pattern
- Use Pydantic models for request/response validation
- Include proper HTTP status codes and error messages
- Background tasks for long-running operations

### CEL Rules
- All expressions must compile before storage
- Use descriptive variable names in evaluation context
- Test rules with sample data before deployment
- Include framework mappings (CIS, NIST, CWE) when available

## Architecture Principles

### Append-Only Data Model
- Configuration snapshots are never updated, only inserted
- IAM edges track effective permissions over time
- Findings maintain complete lifecycle history
- Enables temporal queries and forensic analysis

### Provider Abstraction
- All providers implement `BaseProvider` interface
- Standardized resource discovery and configuration collection
- Consistent error handling and logging
- Support for incremental and full collection modes

### Rule Engine
- CEL-based expressions for cross-platform compatibility
- Cached compilation for performance
- Rich evaluation context with resource, config, principal data
- Extensible for SQL and Rego expressions

### Identity Stitching
- Automatic correlation of identities across providers
- Email-based matching with high confidence
- Name-based matching with lower confidence
- Maintains provenance of stitching decisions

## Security Considerations

### Data Handling
- Never log sensitive credentials or tokens
- Hash configuration data for deduplication
- Maintain audit trail for all data modifications
- Support data retention and deletion policies

### Access Control
- API authentication and authorization required for production
- Role-based access to organizations and findings
- Audit all administrative operations
- Secure credential storage for provider integrations

## Testing Strategy

### Unit Tests
- Test rule compilation and evaluation
- Test provider integrations with mocked APIs
- Test database models and relationships
- Test CLI commands with temporary databases

### Integration Tests
- End-to-end collection and finding generation
- API endpoint testing with real database
- Cross-provider identity stitching
- Temporal query accuracy

### Performance Tests
- Large-scale configuration collection
- Rule evaluation performance
- Database query optimization
- Memory usage under load

## Common Tasks

### Adding a New Provider
1. Create provider class implementing `BaseProvider`
2. Add resource discovery methods
3. Implement configuration collection
4. Add IAM edge discovery
5. Create unit tests
6. Update provider registry

### Adding New Rules
1. Define rule template in `rules/library.py`
2. Test CEL expression compilation
3. Validate against sample data
4. Add framework mappings
5. Include in appropriate control packs

### Extending API
1. Add Pydantic schemas in `api/schemas.py`
2. Create router in `api/routers/`
3. Add endpoints with proper validation
4. Include in main app router
5. Update API documentation

## Deployment

### Production Requirements
- PostgreSQL 14+ with required extensions
- Python 3.11+ with poetry dependencies
- Persistent storage for configuration data
- Network access to provider APIs
- Monitoring and logging infrastructure

### Environment Variables
See `.env.example` for complete configuration options including:
- Database connection strings
- Provider API credentials  
- Security settings
- Logging configuration

## Troubleshooting

### Common Issues
- **Import errors**: Ensure `src/` is in Python path
- **Database connection**: Check PostgreSQL is running and credentials are correct
- **Provider authentication**: Verify API tokens have required permissions
- **Rule compilation**: Test CEL expressions in isolation
- **Missing dependencies**: Run `poetry install` to update packages

### Debugging
- Enable debug logging with `LOG_LEVEL=DEBUG`
- Use `--verbose` flag with CLI commands
- Check database logs for constraint violations
- Validate API responses with `/docs` interface
