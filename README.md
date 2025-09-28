# 🛡️ Cerebro - Enterprise Security System of Record

**The only security platform you'll ever need to deploy.**

Cerebro is a comprehensive, self-hosted security system of record that provides complete visibility into your cloud and SaaS configurations, identities, and permissions across multiple providers. Built with append-only architecture for forensic compliance and featuring a flexible CEL rule engine for portable security policies.

## 🌟 Why Cerebro?

**vs. Commercial Solutions (Prisma, Wiz, Orca)**
- ✅ **Self-hosted** - Your data never leaves your infrastructure
- ✅ **Open rule engine** - CEL expressions, not proprietary DSLs  
- ✅ **Append-only forensic ledger** - Complete audit trail for compliance
- ✅ **Cross-provider identity stitching** - Unified view of users across platforms
- ✅ **Developer-first** - CLI, SDK, CI/CD integration ready
- ✅ **No vendor lock-in** - Standard protocols and open source

## 🚀 Enterprise Features

### **🏗️ Core Architecture**
- **Append-Only Data Model**: Immutable audit history with cryptographic integrity
- **Temporal Queries**: "Who had access to this bucket last Tuesday?" 
- **Hexagonal Architecture**: Clean separation of domain/application/infrastructure
- **Event-Driven Processing**: Real-time configuration change detection

### **🔍 Security Analysis Engine**
- **CEL Rule Engine**: 15+ production-ready security rules with framework mappings
- **Producer Pattern**: Extensible finding generation (inspired by ThreatKey)
- **Multi-Provider Coverage**: GitHub, AWS, GCP, Google Workspace
- **Framework Compliance**: CIS, NIST 800-53, CWE, PCI DSS mappings

### **👥 Identity & Access Management**
- **Cross-Provider Identity Stitching**: Email and name-based correlation
- **Comprehensive IAM Analysis**: Full policy evaluation across providers
- **Permission Temporal Tracking**: Complete access history with provenance
- **Role-Based Access Control**: Granular scopes and audit logging

### **⚡ Enterprise Operations**
- **Background Task Processing**: Celery-based async collection and analysis
- **Bulk Database Operations**: 5-10x performance improvement for large datasets
- **REST API with OpenAPI**: Complete programmatic access
- **CLI Interface**: Operations team tools with rich output
- **Monitoring Ready**: Prometheus metrics, structured logging, health checks

## 🏛️ Architecture

### **Domain Model**
```mermaid
graph TB
    O[Organizations] --> A[Accounts]
    A --> R[Resources]
    A --> P[Principals]
    R --> CS[Config Snapshots]
    P --> IE[IAM Edges]
    R --> IE
    Rules --> F[Findings]
    R --> F
    P --> F
    IC[Identity Clusters] --> P
    U[Users] --> UL[Audit Logs]
    
    subgraph "Append-Only Tables"
        CS
        IE
        F
        UL
    end
```

### **Core Entities**
- **Organizations**: Multi-tenant isolation for companies/business units
- **Accounts**: Provider-specific accounts (GitHub orgs, AWS accounts, GCP projects)
- **Principals**: Users, groups, service accounts, applications across providers
- **Resources**: Cloud/SaaS objects (repos, buckets, VPCs, networks, etc.)
- **Config Snapshots**: Immutable configuration captures with SHA-256 integrity
- **IAM Edges**: Effective permissions with complete temporal tracking
- **Rules**: CEL-based policies with framework mappings (CIS, NIST, CWE)
- **Findings**: Security violations with lifecycle management and evidence
- **Identity Clusters**: Cross-provider identity correlation with confidence scoring
- **Users**: Authentication and authorization with granular scopes

## Quick Start

### Prerequisites
- **Python 3.11+** with UV for dependency management
- **PostgreSQL 14+** with `pgcrypto` and `btree_gin` extensions
- **Redis 6+** for background task processing
- **Provider Access**: GitHub tokens, AWS credentials, etc.

### ⚡ Blazing Fast Setup with UV

```bash
# Install UV (10-100x faster than pip/poetry)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and setup
git clone https://github.com/haasonsaas/cerebro.git
cd cerebro

# One-command setup (uses UV)
make dev && make db-migrate && make dev-data

# Or start everything with Docker
make docker-up

# Access the platform
open http://localhost:8000/docs  # API Documentation  
open http://localhost:5555       # Task Monitor (Flower)
```

### 🔐 First Login

```bash
# Default credentials (change in production)
Username: admin
Password: admin123!

# Or get JWT token via API
curl -X POST "http://localhost:8000/api/v1/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123!"}'
```

### 🔧 Configuration

Essential environment variables (see `.env.example` for complete list):

```env
# Database & Redis
DATABASE_URL=postgresql://user:password@localhost/cerebro
REDIS_URL=redis://localhost:6379/0

# Security (generate with: openssl rand -hex 32)
SECRET_KEY=your-256-bit-secret-key-here

# Provider Credentials
GITHUB_TOKEN=ghp_your_github_token_here
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json

# Optional: Encrypted credential storage
CREDENTIAL_ENCRYPTION_KEY=your-fernet-key-here
```

## 🎯 Usage Examples

### **Data Collection**

```bash
# Create organization
make cli-org-create NAME="Acme Corp"

# Collect configurations (background tasks)
curl -X POST "http://localhost:8000/api/v1/collectors/organizations/{org_id}/collect/background" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"providers": ["github", "aws"]}'

# Monitor collection progress
curl "http://localhost:8000/api/v1/collectors/tasks/{task_id}" \
  -H "Authorization: Bearer $TOKEN"

# CLI collection
make cli-collect ORG="Acme Corp" PROVIDER=github
```

### **Security Analysis**

```bash
# Generate findings (background)
curl -X POST "http://localhost:8000/api/v1/findings/organizations/{org_id}/generate" \
  -H "Authorization: Bearer $TOKEN"

# List critical findings
curl "http://localhost:8000/api/v1/findings?severity=critical&status=open" \
  -H "Authorization: Bearer $TOKEN"

# Get finding statistics
curl "http://localhost:8000/api/v1/findings/organizations/{org_id}/stats" \
  -H "Authorization: Bearer $TOKEN"

# CLI analysis
make cli-findings ORG="Acme Corp"
```

### **Identity Management**

```bash
# View cross-provider identities
curl "http://localhost:8000/api/v1/principals/{principal_id}/permissions" \
  -H "Authorization: Bearer $TOKEN"

# Identity cluster analysis
curl "http://localhost:8000/api/v1/identity/clusters?org_id={org_id}" \
  -H "Authorization: Bearer $TOKEN"
```

### **Rule Management**

```bash
# List active rules by provider
curl "http://localhost:8000/api/v1/rules?provider=github&is_active=true" \
  -H "Authorization: Bearer $TOKEN"

# Test rule compilation
curl -X POST "http://localhost:8000/api/v1/rules/{rule_id}/test" \
  -H "Authorization: Bearer $TOKEN"

# Create custom rule
make cli-rules action=create name="Custom Rule" \
  expression="resource.provider == 'aws' && config.public == true"
```

## Development

### **Project Structure**

```
cerebro/
├── src/cerebro/
│   ├── api/                    # FastAPI application
│   │   ├── routers/           # API endpoints by domain
│   │   ├── auth.py            # JWT authentication
│   │   └── main.py            # Application entry point
│   ├── application/           # Application services (hexagonal architecture)
│   ├── cli/                   # Command-line interface
│   ├── collectors/            # Configuration collection orchestration
│   ├── core/                  # Core domain models and database
│   │   ├── models.py          # Main database models
│   │   ├── user_models.py     # User management models
│   │   ├── identity_models.py # Identity cluster models
│   │   ├── user_service.py    # User management operations
│   │   ├── credential_service.py # Encrypted credential storage
│   │   └── bulk_operations.py # Performance-optimized DB ops
│   ├── domain/                # Pure domain entities and ports
│   ├── findings/              # Security finding management
│   │   ├── producers/         # Provider-specific finding producers
│   │   │   ├── github/       # GitHub security rules
│   │   │   ├── aws/          # AWS security rules  
│   │   │   └── cross_provider/ # Multi-provider rules
│   │   ├── manager.py         # Finding lifecycle management
│   │   └── evaluator.py       # Rule evaluation engine
│   ├── infrastructure/        # External system adapters
│   ├── providers/             # Cloud/SaaS provider integrations
│   │   ├── github/           # GitHub API integration
│   │   ├── aws/              # AWS API integration
│   │   └── base.py           # Provider interface
│   ├── rules/                 # CEL rule engine and library
│   └── tasks/                 # Background task processing
├── migrations/                # Database schema migrations
├── tests/                     # Comprehensive test suite
├── scripts/                   # Setup and maintenance scripts
├── k8s/                      # Kubernetes deployment manifests
├── docker-compose.yml        # Development environment
├── Dockerfile               # Production container
└── Makefile                 # Development automation
```

### **Development Commands (UV-Powered)**

```bash
# Development workflow  
make dev          # uv sync --extra dev + setup environment
make serve        # uv run uvicorn cerebro.api.main:app --reload
make worker       # uv run celery worker (background processing)
make flower       # uv run celery flower (task monitoring)

# Code quality (lightning fast with UV)
make format       # uv run black . && uv run isort .
make lint        # uv run flake8 + uv run mypy
make test        # uv run pytest (with async support)
make check       # Run all quality checks

# Database operations
make db-migrate   # uv run alembic upgrade head
make db-reset     # uv run alembic downgrade base && upgrade head
make dev-data     # uv run python scripts/setup.py

# Provider testing
make providers-test  # Test all provider authentication
make findings-test   # Test finding generation with sample data
```

### **Direct UV Commands**

```bash
# Dependency management
uv add fastapi                    # Add production dependency
uv add --extra dev pytest        # Add development dependency  
uv remove package-name           # Remove dependency
uv sync --upgrade                # Update all dependencies

# Run commands
uv run uvicorn cerebro.api.main:app --reload  # Start API server
uv run pytest                    # Run tests
uv run python -m cerebro.cli --help          # Use CLI
uv run alembic upgrade head      # Database migrations

# One-off commands
uv run --with httpx python -c "import httpx; print('Works!')"
```

## 📊 Security Rules Library

Cerebro includes **15+ production-ready security rules** covering:

### **GitHub Security**
- Public repositories without branch protection
- Admin users without 2FA
- Organization 2FA enforcement
- Deploy key management
- Repository access controls

### **AWS Security** 
- S3 buckets with public access
- Unencrypted S3 storage
- IAM users without MFA
- EC2 instances with public IPs
- Overprivileged IAM policies

### **Cross-Provider**
- Inconsistent MFA enforcement
- Identity sprawl detection
- Privilege escalation paths

### **Framework Compliance**
- **CIS Controls**: Automated compliance checking
- **NIST 800-53**: Security control mapping
- **CWE**: Vulnerability classification
- **PCI DSS**: Payment security requirements

## 🔒 Enterprise Security Features

### **Authentication & Authorization**
- JWT-based API authentication
- Role-based access control with granular scopes
- Multi-factor authentication support
- Complete audit trail for all user actions

### **Data Protection**
- Encrypted credential storage with Fernet
- Append-only audit logs for compliance
- PII handling with privacy controls
- Data retention and deletion policies

### **Operational Security**
- Background task processing for scalability
- Rate limiting and input validation
- Secure defaults with production hardening
- Network segmentation support

## 🚀 Deployment Options

### **Development**
```bash
make docker-up  # Full stack with Docker Compose
```

### **Production**
- **Docker Swarm**: Multi-node container orchestration
- **Kubernetes**: Enterprise-grade with provided manifests
- **Traditional**: Systemd services with PostgreSQL/Redis
- **Cloud**: AWS ECS, GCP Cloud Run, Azure Container Instances

See [DEPLOYMENT.md](DEPLOYMENT.md) for complete deployment guide.

## 📈 Performance & Scale

### **Proven Performance**
- **5-10x speedup** with bulk database operations
- **Background processing** for large organizations (1000+ resources)
- **Efficient queries** with strategic database indexing
- **Caching** for rule compilation and frequent lookups

### **Enterprise Scale**
- **Multi-tenant** organizations with complete isolation
- **Horizontal scaling** for API servers and workers
- **Database optimization** with partitioning and compression ready
- **Monitoring integration** with Prometheus and Grafana

## 🤝 Contributing

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/amazing-feature`
3. **Follow code standards**: `make check` 
4. **Add tests**: Maintain >90% coverage
5. **Update documentation**: Include examples and usage
6. **Submit pull request**: With detailed description

### **Adding New Providers**
```python
# 1. Create provider class
@register_provider("custom")  
class CustomProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "custom"
    
    # Implement abstract methods...

# 2. Create finding producers  
@register_producer
class CustomSecurityProducer(BaseCustomProducer):
    # Implement security rules...

# 3. Add tests and documentation
```

## 📚 Documentation

- **[API Reference](http://localhost:8000/docs)** - Interactive OpenAPI documentation
- **[Deployment Guide](DEPLOYMENT.md)** - Production deployment instructions  
- **[Developer Guide](AGENTS.md)** - Architecture and contribution guidelines
- **[Security Rules](src/cerebro/rules/library.py)** - Complete rule library
- **[Producer Guide](src/cerebro/findings/producers/)** - Custom rule development

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Built with ❤️ for security teams who need complete visibility without vendor lock-in.**
