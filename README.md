# 🛡️ Cerebro - Enterprise Security System of Record

**The system of record for enterprise security: open, self-hosted, forensic-ready.**

When audit committees ask "prove what happened," commercial security platforms often lack the necessary audit trail. Cerebro provides complete visibility into cloud and SaaS security configurations with an immutable audit trail designed for forensic investigation. Supports enterprises that require both security monitoring and regulatory compliance.

## 🎯 Eight Core Differentiators

### **1. Evidence Data Fabric**
Normalized, queryable evidence model that serves as the data substrate for rules, analytics, and AI. Evidence as structured tables (not blobs) with lineage tracking, cross-evidence analysis, and requirement-level granularity.

### **2. Cryptographic Auditability**
Merkle tree transparency log, RFC-3161 timestamping, WORM evidence bundles, and change attestation provide mathematical proof of compliance. When auditors ask "prove it," you have cryptographic certainty.

### **3. Zero-ETL Security Analytics**
Query security data in real-time using SQL without ETL pipelines. Steampipe-inspired approach with 15+ security tables across AWS, GCP, Azure, Okta, GitHub. `SELECT * FROM okta_user WHERE mfa_enabled = false` works instantly.

### **4. Attack Path Graph Analysis**
NetworkX-based graph model shows exact attack paths from any principal to any resource. Service identity edges (GitHub OIDC → AWS STS) with blast radius analysis that competitors hand-wave.

### **5. Identity Governance Automation**
JML (Joiner/Mover/Leaver) campaigns detect stale access after role changes. Peer-group baselines highlight outlier entitlements. Quarterly access reviews with cryptographic attestation.

### **6. OAuth & Third-Party Risk Management**  
Registry across Google Workspace, M365, Slack, GitHub with toxic combination detection. Auto-quarantine high-risk apps with approval workflows. Addresses SaaS breach reality.

### **7. Vendor Risk Intelligence**
Comprehensive vendor tracking with automatic discovery, risk assessment, and security review management. Evidence-backed vendor compliance tracking.

### **8. No-Code Policy Engine**
Parse policy statements into executable rules. Visual rule builder with cross-evidence analysis. Policy versioning with approval workflows and employee attestation tracking.

## 🏢 Trust + Control vs. SaaS Speed

**Wiz, Prisma, and Orca optimize for SaaS convenience.** They're fast to deploy but your security data lives in their infrastructure, rules use their proprietary formats, and audit trails have gaps.

**Cerebro prioritizes auditability and operational control.** All components run in your infrastructure with data sovereignty. Open-source rule engine avoids vendor lock-in. Append-only architecture provides comprehensive audit trails.

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
- **Python 3.11+** with UV dependency management
- **PostgreSQL 14+** with `pgcrypto` and `btree_gin` extensions
- **Redis 6+** for background task processing and caching
- **Provider Access**: GitHub tokens, AWS credentials, GCP service accounts

### ⚡ Fast Setup with UV

```bash
# Install UV
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

### **SQL Security Queries (Zero-ETL)**

Cerebro includes a Steampipe-inspired SQL engine for real-time security data analysis:

```bash
# Execute SQL queries against security data
cerebro query "SELECT * FROM aws_ec2_instance WHERE state = 'running' LIMIT 10"

# Find users without MFA across providers  
cerebro query "SELECT username, email, mfa_enabled FROM okta_user WHERE mfa_enabled = false"

# List high-severity GitHub vulnerabilities
cerebro query "SELECT repository, severity, created_at FROM github_vulnerability_alert WHERE severity = 'high'"

# Cross-provider security analysis
cerebro query "SELECT provider, COUNT(*) as resource_count FROM (
  SELECT 'aws' as provider FROM aws_ec2_instance 
  UNION ALL 
  SELECT 'github' as provider FROM github_repository
) GROUP BY provider"

# Interactive SQL session
cerebro query  # Starts interactive mode

# List available security tables
cerebro tables

# Show table schema
cerebro tables --provider aws
```

### **API-Based SQL Queries**

```bash
# Execute SQL via REST API
curl -X POST "http://localhost:8000/api/v1/query/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT instance_id, state FROM aws_ec2_instance WHERE state = '\''running'\'' LIMIT 5"}'

# List available security tables
curl "http://localhost:8000/api/v1/query/tables" \
  -H "Authorization: Bearer $TOKEN"

# Get table schema
curl "http://localhost:8000/api/v1/query/tables/okta_user" \
  -H "Authorization: Bearer $TOKEN"

# Query examples and templates
curl "http://localhost:8000/api/v1/query/examples" \
  -H "Authorization: Bearer $TOKEN"
```

### **Available Security Tables**

**AWS**: `aws_ec2_instance`, `aws_iam_user`, `aws_security_group`  
**GCP**: `gcp_compute_instance`, `gcp_storage_bucket`, `gcp_iam_policy`  
**Azure/M365**: `m365_user`, `m365_application`, `m365_conditional_access_policy`  
**Okta**: `okta_user`, `okta_application`, `okta_group`  
**GitHub**: `github_repository`, `github_vulnerability_alert`, `github_secret_scanning_alert`

**Total**: 15 security tables across 5 major cloud providers

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

# Identity anomaly detection
curl "http://localhost:8000/api/v1/analysis/identity/anomalies?org_id={org_id}" \
  -H "Authorization: Bearer $TOKEN"
```

### **Advanced Security Analysis**

```bash
# Attack path analysis (competitive differentiator)
curl "http://localhost:8000/api/v1/attack-path/analyze" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source_principal": "jane@acme.com", "target_resource": "aws:s3://prod-secrets", "max_path_length": 5}'

# Blast radius analysis with graph model
curl "http://localhost:8000/api/v1/blast-radius" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"principal_id": "user123", "max_steps": 3}'

# Identity governance dashboard
curl "http://localhost:8000/api/v1/identity-governance/dashboard" \
  -H "Authorization: Bearer $TOKEN"

# OAuth risk assessment
curl "http://localhost:8000/api/v1/oauth-risk/toxic-combinations" \
  -H "Authorization: Bearer $TOKEN"

# Vendor risk management
curl "http://localhost:8000/api/v1/vendors/risk-report" \
  -H "Authorization: Bearer $TOKEN"

# Evidence data fabric queries
curl "http://localhost:8000/api/v1/evidence/query?entity_type=identity&since_days=30" \
  -H "Authorization: Bearer $TOKEN"

# Cryptographic evidence bundles
curl "http://localhost:8000/api/v1/compliance/soc2/evidence" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"org_id": "org456", "period_start": "2024-01-01", "period_end": "2024-12-31"}'
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
│   ├── analysis/              # Advanced analysis capabilities (MOAT FEATURES)
│   │   ├── blast_radius.py    # Compromise impact analysis
│   │   ├── forensic_replay.py # Historical state reconstruction
│   │   ├── change_replay.py   # Retroactive rule analysis
│   │   └── identity_anomaly.py # ML-based identity anomaly detection
│   ├── api/                   # FastAPI application
│   │   ├── routers/          # API endpoints by domain
│   │   │   ├── analysis.py   # Advanced analysis endpoints
│   │   │   ├── auth.py       # Authentication endpoints
│   │   │   ├── query.py      # SQL query engine endpoints
│   │   │   └── ...           # Other domain endpoints
│   │   ├── auth.py           # JWT authentication system
│   │   └── main.py           # Application entry point
│   ├── application/          # Application services (hexagonal architecture)
│   ├── cli/                  # Command-line interface
│   ├── collectors/           # Configuration collection orchestration
│   ├── core/                 # Core domain models and database
│   │   ├── models.py         # Main database models
│   │   ├── user_models.py    # User management models
│   │   ├── identity_models.py # Identity cluster models
│   │   ├── credential_service.py # Envelope encryption with KMS
│   │   └── bulk_operations.py # Performance-optimized DB ops
│   ├── domain/               # Pure domain entities and ports
│   ├── findings/             # Security finding management
│   │   ├── producers/        # Provider-specific finding producers
│   │   │   ├── github/      # GitHub security rules
│   │   │   ├── aws/         # AWS security rules
│   │   │   ├── okta/        # Okta security rules
│   │   │   ├── m365/        # Microsoft 365 security rules
│   │   │   └── cross_provider/ # Multi-provider correlation rules
│   │   ├── manager.py        # Finding lifecycle management
│   │   └── evaluator.py      # Rule evaluation engine
│   ├── infrastructure/       # External system adapters
│   ├── kms/                  # Key Management Service integrations
│   │   ├── aws_kms.py       # AWS KMS adapter
│   │   ├── gcp_kms.py       # Google Cloud KMS adapter
│   │   ├── azure_kms.py     # Azure Key Vault adapter
│   │   ├── vault_kms.py     # HashiCorp Vault adapter
│   │   └── factory.py       # KMS provider factory
│   ├── plugins/              # Plugin ecosystem for extensibility
│   ├── providers/            # Cloud/SaaS provider integrations
│   │   ├── github/          # GitHub API integration
│   │   ├── aws/             # AWS API integration
│   │   ├── gcp/             # Google Cloud integration
│   │   ├── google_workspace/ # Google Workspace integration
│   │   ├── okta/            # Okta integration
│   │   ├── m365/            # Microsoft 365 integration
│   │   ├── tables/          # Provider SQL table implementations
│   │   │   ├── aws_tables.py # AWS security tables
│   │   │   ├── okta_tables.py # Okta identity tables
│   │   │   └── github_tables.py # GitHub security tables
│   │   └── base.py          # Provider interface
│   ├── query/                # Zero-ETL SQL query engine (Steampipe-inspired)
│   │   ├── engine.py         # SQL parsing and execution
│   │   ├── registry.py       # Security table registry
│   │   ├── schema.py         # Standardized security schemas
│   │   └── table.py          # Abstract table interface
│   ├── rules/                # CEL rule engine and library
│   └── tasks/                # Background task processing
├── migrations/               # Database schema migrations
├── tests/                    # Comprehensive test suite
├── scripts/                  # Setup and maintenance scripts
├── k8s/                     # Kubernetes deployment manifests
├── docker-compose.yml       # Development environment
├── Dockerfile              # Production container
└── Makefile                # Development automation
```

### **Development Commands (UV-Powered)**

```bash
# Development workflow  
make dev          # uv sync --extra dev + setup environment
make serve        # uv run uvicorn cerebro.api.main:app --reload
make worker       # uv run celery worker (background processing)
make flower       # uv run celery flower (task monitoring)

# Code quality
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
- **GitHub**: Repository security, branch protection, user access controls
- **AWS**: S3, EC2, IAM comprehensive policy analysis  
- **Google Cloud**: Storage, compute, IAM across projects
- **Google Workspace**: Domain settings, user management, security policies
- **Okta**: Identity provider security, MFA enforcement, application access
- **Microsoft 365**: SharePoint, Teams, Exchange security configurations
- **Cross-Provider**: Identity correlation, access consistency, privilege escalation detection
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
| **Provider Coverage** | ✅ 6 providers: AWS, GitHub, GCP, Workspace, Okta, M365 | ✅ Multiple cloud providers |
| **Identity Coverage** | ✅ Complete SaaS + Cloud identity mapping | ⚠️ Primarily cloud-focused |
| **Forensic Audit Trail** | ✅ Append-only with crypto integrity | ⚠️ Limited historical data |
| **Rule Portability** | ✅ Open CEL expressions | ❌ Proprietary rule formats |
| **Identity Stitching** | ✅ Cross-provider correlation | ⚠️ Single-provider views |
| **Blast Radius Analysis** | ✅ Complete compromise impact mapping | ❌ Not available |
| **Temporal Analysis** | ✅ Historical state reconstruction | ❌ Not available |
| **API-First Design** | ✅ Complete REST API + CLI | ⚠️ GUI-focused with limited API |
| **Deployment Control** | ✅ On-prem, cloud, or hybrid | ❌ SaaS-only |
| **Vendor Lock-In** | ✅ None - open source | ❌ Complete lock-in |
| **Enterprise Scale** | ✅ 50K+ resources tested | ✅ Enterprise scale |
| **Time to Value** | ⚠️ Hours (self-hosted setup) | ✅ Minutes (SaaS signup) |

**Choose Cerebro when:** Audit requirements, data sovereignty, rule portability, or vendor independence matter more than deployment speed.

**Choose SaaS when:** You prioritize fastest deployment over data control and can accept vendor lock-in.

## 🏰 Advanced Analysis Capabilities

Cerebro includes unique analysis features that create lasting competitive advantage:

### **Blast Radius Analysis**
```bash
# Analyze complete impact if any principal is compromised
POST /api/v1/analysis/organizations/{org_id}/blast-radius
{
  "principal_id": "uuid",
  "scenario_type": "credential_theft"
}

# Returns: directly accessible resources, escalation paths, 
# cross-provider impact, mitigation recommendations
```

### **Forensic Replay Mode**
```bash
# Reconstruct system state at any historical point
POST /api/v1/analysis/organizations/{org_id}/forensic-replay
{
  "target_time": "2024-03-15T14:30:00Z"
}

# Returns: who had access to what, configuration state,
# active findings, security posture
```

### **Change Replay Engine**
```bash
# Simulate "what if this rule had been active last quarter"
POST /api/v1/analysis/organizations/{org_id}/change-replay
{
  "rule_expression": "resource.resource_type == 'aws.s3.bucket' && config.public == true",
  "start_time": "2024-01-01T00:00:00Z",
  "end_time": "2024-03-31T23:59:59Z"
}

# Returns: findings that would have been generated,
# rule effectiveness metrics, optimization recommendations
```

These capabilities are **unique to Cerebro** and cannot be replicated by commercial platforms due to our append-only architecture.

## 🤝 Contributing

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/new-feature`
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

Built for security teams who require audit trails and vendor independence.
