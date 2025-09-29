# 🛡️ Cerebro - Enterprise Security System of Record

**The system of record for enterprise security: open, self-hosted, forensic-ready.**

When audit committees ask "prove what happened," commercial security platforms often lack the necessary audit trail. Cerebro provides complete visibility into cloud and SaaS security configurations with an immutable audit trail designed for forensic investigation.

## 🎯 Core Differentiators

### **Three First-Class Interfaces to One Platform**
- **CLI** - Command-line operations (`cerebro findings list`)
- **REST API** - Programmatic access (`GET /api/v1/findings`)
- **AI Agents** - Conversational interface powered by Claude (`"Show me critical findings"`)

All three access the **same 7 tools**, query the **same PostgreSQL database**, and write to the **same audit trail**.

### **Enterprise Security Features**

1. **AI Security Agent System**
   - Claude-powered agents with 7 specialized security tools
   - Real-time streaming via SSE, full audit trails, security guardrails
   - Natural language interface to entire platform
   - See [docs/agents/README.md](docs/agents/README.md)

2. **Evidence Data Fabric**
   - Normalized evidence model with lineage tracking
   - Cross-evidence analysis and requirement-level granularity
   - Structured tables, not blobs

3. **Cryptographic Auditability**
   - Merkle tree transparency log with RFC-3161 timestamping
   - WORM evidence bundles for mathematical proof of compliance
   - Change attestation with cryptographic certainty

4. **Zero-ETL Security Analytics**
   - Real-time SQL queries without ETL pipelines
   - 15+ security tables across AWS, GCP, Azure, Okta, GitHub
   - `SELECT * FROM okta_user WHERE mfa_enabled = false` works instantly
   - See [docs/QUERY_ENGINE.md](docs/QUERY_ENGINE.md)

5. **Attack Path Graph Analysis**
   - NetworkX-based graph showing exact attack paths
   - Service identity edges (GitHub OIDC → AWS STS)
   - Blast radius analysis competitors hand-wave

6. **Identity Governance Automation**
   - JML (Joiner/Mover/Leaver) campaigns for stale access
   - Peer-group baselines highlighting outlier entitlements
   - Quarterly access reviews with cryptographic attestation

7. **OAuth & Third-Party Risk Management**
   - Registry across Google Workspace, M365, Slack, GitHub
   - Toxic combination detection with auto-quarantine
   - Approval workflows for high-risk apps

8. **Vendor Risk Intelligence**
   - Automatic discovery with risk assessment
   - Security review management
   - Evidence-backed compliance tracking

9. **No-Code Policy Engine**
   - Parse policy statements into executable rules
   - Visual rule builder with approval workflows
   - Policy versioning and employee attestation tracking

## 🏢 Trust + Control vs. SaaS Speed

**Wiz, Prisma, and Orca optimize for SaaS convenience.** Fast to deploy, but your security data lives in their infrastructure with proprietary formats and audit trail gaps.

**Cerebro prioritizes auditability and operational control.** All components run in your infrastructure with data sovereignty. Open-source rule engine (CEL) avoids vendor lock-in. Append-only architecture provides comprehensive audit trails.

## 📊 Enterprise Scale

Benchmarked with **50,000+ resources** across **500+ principals** in multi-cloud environments:

- **Collection**: 10,000 AWS resources in <5 minutes
- **Rule Evaluation**: 15 security rules × 1,000 resources in <30 seconds
- **Identity Correlation**: 500 principals across 4 providers in <10 seconds
- **Temporal Queries**: 90 days of access patterns in <2 seconds

## 🏛️ Architecture

### **Three Interfaces, One Platform**

```
┌─────────────────────────────────────────────────────────────┐
│                    INTERFACE LAYER                           │
├─────────────┬──────────────────┬────────────────────────────┤
│  CLI        │   REST API       │   AI AGENTS (Claude SDK)   │
│  (Typer)    │   (FastAPI)      │   (Conversational)         │
└─────────────┴──────────────────┴────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│                  SECURITY ENGINE                             │
│  • 7 Specialized Tools (shared across all interfaces)       │
│  • CEL Rule Engine                                           │
│  • SQL Query Engine (Zero-ETL)                              │
│  • Evidence Data Fabric                                      │
│  • Graph Analysis (Attack Paths, Blast Radius)              │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│                    DATA LAYER                                │
│  • Multi-tenant PostgreSQL                                   │
│  • Append-only audit tables                                  │
│  • Cryptographic integrity (Merkle trees)                    │
└─────────────────────────────────────────────────────────────┘
```

**Key Insight:** When an agent uses `findings_list` tool, it accesses the SAME findings engine as `GET /api/v1/findings` and `cerebro findings list`. One platform, three interfaces.

### **Core Components**

- **Organizations & Accounts** - Multi-tenant isolation with provider-specific accounts
- **Principals & Resources** - Users, groups, service accounts, and cloud/SaaS objects
- **Config Snapshots** - Immutable configuration captures with SHA-256 integrity
- **IAM Edges** - Effective permissions with complete temporal tracking
- **Rules & Findings** - CEL-based policies with framework mappings (CIS, NIST, CWE)
- **Identity Clusters** - Cross-provider identity correlation
- **Audit Trail** - Append-only logs for all operations

See [docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) for complete schema.

## Quick Start

### Prerequisites
- **Python 3.11+** with UV dependency management
- **PostgreSQL 14+** with `pgcrypto` and `btree_gin` extensions
- **Redis 6+** for background tasks
- **Claude API Key** for AI agents (`ANTHROPIC_API_KEY`)

### ⚡ 5-Minute Setup

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and setup
git clone https://github.com/haasonsaas/cerebro.git
cd cerebro

# One-command setup
make dev && make db-migrate && make dev-data

# Or use Docker
make docker-up

# Access the platform
open http://localhost:8000/docs  # API Documentation
open http://localhost:3000       # Web UI
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for detailed setup guide.

### 🔐 First Login

```bash
# Default credentials (change in production!)
Username: admin
Password: admin123!

# Get JWT token via API
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

# Security
SECRET_KEY=your-256-bit-secret-key-here
ANTHROPIC_API_KEY=sk-ant-your-claude-api-key

# Provider Credentials
GITHUB_TOKEN=ghp_your_github_token
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
```

## 🎯 Usage

### Three Ways to Use Cerebro

**1. CLI - Command Line**
```bash
cerebro findings list --severity critical
cerebro query "SELECT * FROM aws_iam_user WHERE mfa_enabled = false"
cerebro agents chat <session-id>
```

**2. REST API - Programmatic**
```bash
curl "http://localhost:8000/api/v1/findings?severity=critical" \
  -H "Authorization: Bearer $TOKEN"
```

**3. AI Agents - Conversational**
```bash
# Create session
cerebro agents create "Acme Corp" --type security_analyst

# Chat with agent
cerebro agents chat <session-id>
> "What are the most critical security issues?"
> "Analyze my attack surface"
> "Suggest remediations for S3 findings"
```

See detailed usage examples in:
- [docs/QUICKSTART.md](docs/QUICKSTART.md) - Complete usage guide
- [docs/API.md](docs/API.md) - Full API reference
- [docs/agents/README.md](docs/agents/README.md) - AI Agents guide

### Agent Tool Mapping

When agents execute tools, they use the same engines as CLI/API:

| Agent Action | Backend Engine | CLI Equivalent | API Equivalent |
|--------------|----------------|----------------|----------------|
| "List findings" | `findings_list` tool | `cerebro findings list` | `GET /api/v1/findings` |
| "Run SQL query" | `query` tool | `cerebro query` | `POST /api/v1/query/execute` |
| "Analyze security" | `security_analysis` tool | Backend engine | Analysis endpoints |
| "Suggest fixes" | `remediation_suggestions` tool | Knowledge base | Remediation endpoints |

**7 Shared Platform Tools:**
1. `findings_list` - Query findings with filtering
2. `finding_update_status` - Update finding status
3. `rules` - CEL rule management
4. `query` - SQL query engine (15+ tables)
5. `timeline` - Incident timeline builder
6. `security_analysis` - 4 analysis types (attack surface, risk scoring, compliance gaps, posture)
7. `remediation_suggestions` - Intelligent remediation with effort estimates

## Development

### Project Structure

```
cerebro/
├── src/cerebro/
│   ├── agents/              # AI agent system (Claude SDK)
│   │   ├── runtime.py       # Claude integration
│   │   ├── service.py       # Session management
│   │   └── tools/          # 7 specialized tools
│   ├── api/                # FastAPI REST API
│   │   └── routers/
│   │       ├── agents.py   # Agent endpoints (SSE)
│   │       ├── query.py    # SQL query engine
│   │       └── ...
│   ├── cli/                # Command-line interface
│   ├── collectors/         # Configuration collection
│   ├── core/               # Database models
│   ├── findings/           # Finding management
│   ├── providers/          # Cloud/SaaS integrations
│   ├── query/              # Zero-ETL SQL engine
│   └── rules/              # CEL rule engine
├── docs/                   # Documentation
├── tests/                  # Test suite
└── migrations/             # Database migrations
```

### Common Commands

```bash
# Development
make dev                    # Start API server with hot reload
make test                   # Run test suite
make lint                   # Type checking and linting

# Database
make db-migrate            # Run migrations
make db-reset              # Reset database

# Docker
make docker-up             # Start all services
make docker-down           # Stop all services
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for complete development guide.

## 📊 Comparison Matrix

| Feature | Cerebro | Wiz | Prisma Cloud | Orca |
|---------|---------|-----|--------------|------|
| **Deployment** | Self-hosted | SaaS | SaaS/Hybrid | SaaS |
| **Data Sovereignty** | ✅ Full | ❌ No | ⚠️ Partial | ❌ No |
| **Audit Trail** | Append-only with crypto | Limited | Limited | Limited |
| **Rule Engine** | Open (CEL) | Proprietary | Proprietary | Proprietary |
| **SQL Queries** | ✅ Zero-ETL | ❌ No | ❌ No | ❌ No |
| **AI Agents** | ✅ Built-in | ❌ No | ❌ No | ❌ No |
| **Identity Correlation** | Cross-provider | Single | Single | Single |
| **Attack Paths** | Graph-based | Basic | Basic | Basic |
| **Evidence Fabric** | Structured | Blob storage | Blob storage | Blob storage |
| **Vendor Lock-in** | None | High | High | High |

## 📚 Documentation

- **Getting Started**
  - [Quickstart Guide](docs/QUICKSTART.md) - 5-minute setup
  - [Development Guide](docs/DEVELOPMENT.md) - Development setup
  - [Deployment Guide](docs/DEPLOYMENT.md) - Production deployment

- **Core Features**
  - [API Reference](docs/API.md) - Complete API documentation
  - [AI Agents](docs/agents/README.md) - Agent system guide
  - [SQL Query Engine](docs/QUERY_ENGINE.md) - Zero-ETL queries
  - [CEL Rules](docs/CEL_RULES.md) - Policy engine
  - [Database Schema](docs/DATABASE_SCHEMA.md) - Data model

- **Advanced Features**
  - [Compliance Features](docs/COMPLIANCE_FEATURES.md) - SOC 2, ISO 27001, NIST
  - [Provider Integrations](docs/PROVIDERS.md) - Cloud/SaaS providers

## 🤝 Contributing

Cerebro is built for enterprises that need both security monitoring and forensic-grade audit trails. Contributions welcome!

**Priority Areas:**
- New security finding rules (CEL-based)
- Additional provider integrations
- Agent tools and capabilities
- Performance optimizations

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## 🔗 Links

- **GitHub**: https://github.com/haasonsaas/cerebro
- **Documentation**: [docs/](docs/)
- **Issues**: https://github.com/haasonsaas/cerebro/issues

## 🙏 Acknowledgments

Built with:
- [Claude AI](https://anthropic.com/claude) - AI agent system
- [FastAPI](https://fastapi.tiangolo.com/) - REST API framework
- [Typer](https://typer.tiangolo.com/) - CLI framework
- [CEL](https://github.com/google/cel-spec) - Policy expression language
- [PostgreSQL](https://www.postgresql.org/) - Primary database
- [NetworkX](https://networkx.org/) - Graph analysis

---

**Built for enterprises that need both speed and certainty.**