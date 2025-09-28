# Cerebro - Security System of Record

A pragmatic security system of record capable of ingesting and auditing configurations, identities and access edges from GitHub, Google Workspace, AWS and GCP. Features append-only storage and a flexible CEL (Common Expression Language) rule engine.

## Features

- **Append-Only Architecture**: Complete audit history with immutable configuration snapshots
- **CEL Rule Engine**: Flexible, portable policies using Common Expression Language
- **Multi-Provider Support**: GitHub, AWS, GCP, Google Workspace integrations
- **Real-time Monitoring**: Continuous configuration and permission tracking
- **Finding Management**: Automated misconfiguration detection with suppression support

## Architecture

### Core Entities
- **Organizations**: Top-level tenants (companies/business units)
- **Accounts**: Provider-specific accounts (GitHub orgs, AWS accounts, etc.)
- **Principals**: Users, groups, service accounts, and applications
- **Resources**: Cloud/SaaS objects (repos, buckets, networks, etc.)
- **Config Snapshots**: Append-only configuration captures
- **IAM Edges**: Effective permissions with temporal tracking
- **Rules**: CEL-based policy definitions
- **Findings**: Materialized violations and misconfigurations

## Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL 14+ with `pgcrypto` and `btree_gin` extensions
- Poetry for dependency management

### Installation

```bash
# Clone repository
git clone <repository-url>
cd cerebro

# Install dependencies
poetry install

# Set up environment
cp .env.example .env
# Edit .env with your configuration

# Run migrations
poetry run alembic upgrade head

# Start development server
poetry run uvicorn cerebro.api.main:app --reload
```

### Configuration

Create a `.env` file with the following variables:

```env
# Database
DATABASE_URL=postgresql://user:password@localhost/cerebro

# Provider Credentials
GITHUB_TOKEN=ghp_...
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json

# Security
SECRET_KEY=your-secret-key
```

## Usage

### Running Collectors

```bash
# Collect GitHub configurations
poetry run cerebro collect github --org your-org

# Collect AWS configurations  
poetry run cerebro collect aws --account 123456789012

# Collect all providers
poetry run cerebro collect all
```

### Managing Rules

```bash
# List active rules
poetry run cerebro rules list

# Create a new rule
poetry run cerebro rules create --name "Public S3 Bucket" \
  --expression "resource.resource_type == 'aws.s3.bucket' && config.public == true" \
  --severity high
```

### API Documentation

Once running, visit `http://localhost:8000/docs` for interactive API documentation.

## Development

### Project Structure

```
cerebro/
├── src/cerebro/
│   ├── core/              # Core models and database
│   ├── providers/         # Provider integrations
│   ├── collectors/        # Configuration collectors
│   ├── rules/            # CEL rule engine
│   ├── findings/         # Finding management
│   ├── api/              # FastAPI endpoints
│   └── cli/              # Command-line interface
├── migrations/           # Database migrations
├── tests/               # Test suite
└── scripts/             # Utility scripts
```

### Running Tests

```bash
poetry run pytest
poetry run pytest --cov=cerebro  # with coverage
```

### Code Quality

```bash
poetry run black .
poetry run isort .
poetry run mypy .
poetry run flake8 .
```

## License

MIT License - see LICENSE file for details.
