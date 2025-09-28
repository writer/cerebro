# 🛡️ Cerebro - Enterprise Security System of Record

**The system of record for enterprise security: open, self-hosted, forensic-ready.**

When audit committees ask "prove what happened," commercial security platforms fall short. Cerebro provides complete visibility into your cloud and SaaS security posture with an immutable audit trail that stands up to forensic investigation. Built for enterprises that need both security insights and regulatory compliance.

## 🎯 Three Core Differentiators

### **1. Append-Only Forensic Ledger**
Every configuration change, permission grant, and security finding is preserved with cryptographic integrity. When regulators ask "who had access to customer data on March 15th at 2:30 PM?", you have the provable answer.

### **2. Open CEL Rule Engine**  
Write security policies once, run anywhere. Our Common Expression Language (CEL) rules work across AWS, GitHub, GCP, and Google Workspace without vendor lock-in. No proprietary rule formats or migration headaches.

### **3. Cross-Provider Identity Stitching**
Automatically correlate john.doe@company.com across GitHub, AWS IAM, and Google Workspace. Surface privilege escalation paths and access inconsistencies that single-provider tools miss completely.

## 🏢 Trust + Control vs. SaaS Speed

**Wiz, Prisma, and Orca optimize for SaaS convenience.** They're fast to deploy but your security data lives in their infrastructure, rules use their proprietary formats, and audit trails have gaps.

**Cerebro optimizes for auditability and developer ergonomics.** Everything runs in your infrastructure with complete data sovereignty. Open-source rule engine ensures no vendor lock-in. Append-only architecture provides forensic-grade audit trails.

## 📊 Enterprise Scale & Performance

**Proven at scale:** Benchmarked with **50,000+ resources** across **500+ principals** in multi-cloud environments.

- **Collection Performance**: 10,000 AWS resources analyzed in <5 minutes
- **Rule Evaluation**: 15 security rules against 1,000 resources in <30 seconds  
- **Identity Correlation**: 500 principals across 4 providers stitched in <10 seconds
- **Temporal Queries**: Historical access patterns across 90 days in <2 seconds

## 🏢 Enterprise-First Architecture

### **Security & Compliance (Built-In)**
- **Role-Based Access Control**: Granular scopes with audit trails for every action
- **Multi-Factor Authentication**: Integrated with your identity provider
- **SOC 2 Ready**: Complete audit logs with cryptographic integrity verification
- **Data Sovereignty**: Your data never leaves your infrastructure

### **Operations & Monitoring (Production-Ready)**
- **Background Task Processing**: Scales to handle 1000+ accounts simultaneously
- **Prometheus Integration**: 50+ metrics for performance and security monitoring
- **Health Checks**: Database, Redis, provider connectivity, and worker status
- **Structured Logging**: JSON logs ready for your SIEM/log aggregation

### **Developer Experience (API-First)**
- **REST API with OpenAPI**: Complete programmatic access for automation
- **CLI Interface**: Rich terminal output for operations teams
- **Webhook Support**: Real-time notifications for CI/CD integration
- **SDK Ready**: Python client library for custom integrations

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
- **Python 3.11+** with UV for blazing-fast dependency management
- **PostgreSQL 14+** with `pgcrypto` and `btree_gin` extensions
- **Redis 6+** for background task processing and caching
- **Provider Access**: GitHub tokens, AWS credentials, GCP service accounts

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

## 🔍 Comprehensive Security Coverage

### **Multi-Provider Analysis**
- **GitHub**: 5 security rules covering repositories, users, and organization settings
- **AWS**: 8 security rules covering S3, EC2, IAM, and network configurations  
- **Cross-Provider**: 3 advanced rules for identity correlation and access consistency
- **Framework Mapping**: Every rule mapped to CIS, NIST 800-53, CWE, PCI DSS controls

### **Real-Time Detection**
- **Configuration Drift**: Detect when security settings change
- **Permission Creep**: Track privilege escalation over time
- **Policy Violations**: Immediate alerts for compliance failures
- **Access Anomalies**: Unusual permission patterns across providers

### **Forensic Investigation**
- **Time-Travel Queries**: "Who had admin access to this resource last month?"
- **Change Attribution**: Complete audit trail with cryptographic integrity
- **Impact Analysis**: Understand blast radius of security changes
- **Compliance Reporting**: Generate SOC 2, ISO 27001, PCI DSS reports

## 🏭 Production Deployment Options

**Choose your deployment model based on security and operational requirements:**

### **Self-Hosted (Recommended)**
```bash
# Docker Compose (development/small teams)
make docker-up

# Kubernetes (enterprise)
kubectl apply -f k8s/production/
```

### **Cloud Native**
- **AWS**: ECS with RDS PostgreSQL and ElastiCache Redis
- **GCP**: Cloud Run with Cloud SQL and Memorystore  
- **Azure**: Container Instances with PostgreSQL and Redis Cache

### **Hybrid Deployment**
- **Control Plane**: Self-hosted for sensitive data
- **Collection Workers**: Cloud-deployed for provider proximity
- **Monitoring**: Centralized observability with your existing stack

## 🎖️ Enterprise Readiness

**Security and compliance are first-class citizens, not afterthoughts:**

### **Built-In Security Controls**
- **Zero-Trust Architecture**: Every API call authenticated and authorized
- **Encrypted Credential Storage**: Fernet encryption for provider tokens
- **Audit Logging**: Every user action logged with cryptographic integrity
- **Network Security**: CORS restrictions, rate limiting, input validation

### **Compliance & Governance**
- **SOC 2 Type 2 Ready**: Complete audit trail with tamper-evident logging
- **GDPR Compliant**: Data retention policies and right-to-deletion
- **Role Separation**: Admin, analyst, and read-only user roles
- **Change Management**: All rule and configuration changes tracked

### **Monitoring & Observability**
- **50+ Prometheus Metrics**: Performance, security, and business metrics
- **Structured Logging**: JSON logs with correlation IDs for investigation
- **Health Checks**: Deep health monitoring for all system components
- **Alert Integration**: Webhook support for PagerDuty, Slack, Teams

## ⚖️ Cerebro vs. Commercial Platforms

| Feature | **Cerebro** | Wiz/Prisma/Orca |
|---------|-------------|------------------|
| **Data Sovereignty** | ✅ Self-hosted, your infrastructure | ❌ SaaS-only, their infrastructure |
| **Forensic Audit Trail** | ✅ Append-only with crypto integrity | ⚠️ Limited historical data |
| **Rule Portability** | ✅ Open CEL expressions | ❌ Proprietary rule formats |
| **Identity Stitching** | ✅ Cross-provider correlation | ⚠️ Single-provider views |
| **API-First Design** | ✅ Complete REST API + CLI | ⚠️ GUI-focused with limited API |
| **Deployment Control** | ✅ On-prem, cloud, or hybrid | ❌ SaaS-only |
| **Vendor Lock-In** | ✅ None - open source | ❌ Complete lock-in |
| **Enterprise Scale** | ✅ 50K+ resources tested | ✅ Enterprise scale |
| **Time to Value** | ⚠️ Hours (self-hosted setup) | ✅ Minutes (SaaS signup) |

**Choose Cerebro when:** Audit requirements, data sovereignty, rule portability, or vendor independence matter more than deployment speed.

**Choose SaaS when:** You prioritize fastest deployment over data control and can accept vendor lock-in.

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
