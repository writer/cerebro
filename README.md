# Cerebro - Security System of Record

Self-hosted security platform with forensic-ready audit trails.

## What It Does

Cerebro tracks security configurations across cloud providers and SaaS platforms. It maintains an immutable audit trail of all changes for compliance and forensic investigation.

### Key Features

- **Three interfaces**: CLI, REST API, AI agents - all access the same data
- **SQL queries**: Direct SQL access to security data without ETL pipelines
- **Agent system**: 21 specialized tools for security investigation and compliance
- **Audit trail**: Append-only logs with cryptographic integrity
- **Attack path analysis**: Graph-based analysis showing lateral movement
- **Compliance automation**: Automated testing for SOC2, ISO27001, CIS, NIST

## Architecture

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
│  • 21 Specialized Tools                                      │
│  • CEL Rule Engine                                           │
│  • SQL Query Engine                                          │
│  • Graph Analysis                                            │
│  • Forensic Replay                                           │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│                    DATA LAYER                                │
│  • PostgreSQL                                                │
│  • Append-only audit tables                                  │
│  • Cryptographic integrity                                   │
└─────────────────────────────────────────────────────────────┘
```

### Agent Tools (21 total)

**Investigation**
- `forensic_replay` - Historical state reconstruction
- `change_replay` - Change timeline between timestamps
- `simulate_attack_path` - Attack path discovery
- `calculate_blast_radius` - Impact scope calculation
- `hunt_identity_anomalies` - ML-powered anomaly detection

**Compliance**
- `test_compliance_control` - Automated control testing
- `build_evidence_bundle` - Cryptographically-signed evidence

**Core Operations**
- `findings_list` - Query findings
- `finding_update_status` - Update findings
- `rules` - Rule management
- `query` - SQL queries
- `timeline` - Incident timelines
- `remediation` - Intelligent remediation

**Context & Knowledge**
- `get_org_context` - Organizational awareness
- `get_system_context` - System/infrastructure context
- `remember_context` - Cross-session memory
- `get_session_history` - Conversation history

**Code Understanding**
- `read_code` - Read source files
- `search_code` - Find code symbols

**Analysis**
- `summarize_finding` - Plain English explanations
- `security_analysis` - Attack surface analysis

## Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL 14+
- Redis 6+
- Claude API key (for AI agents)

### Setup

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and setup
git clone https://github.com/WriterInternal/cerebro.git
cd cerebro

# One-command setup
make dev && make db-migrate && make dev-data

# Or use Docker
make docker-up

# Access
open http://localhost:8000/docs  # API
open http://localhost:3000       # Web UI
```

Default credentials: `admin` / `admin123!`

### Configuration

Essential environment variables:

```env
DATABASE_URL=postgresql://user:password@localhost/cerebro
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=your-256-bit-secret-key
ANTHROPIC_API_KEY=sk-ant-your-key
```

## Usage

### CLI

```bash
cerebro findings list --severity critical
cerebro query "SELECT * FROM aws_iam_user WHERE mfa_enabled = false"
cerebro agents chat <session-id>
```

### REST API

```bash
curl "http://localhost:8000/api/v1/findings?severity=critical" \
  -H "Authorization: Bearer $TOKEN"
```

### AI Agents

```bash
# Create session
cerebro agents create "Acme Corp" --type security_analyst

# Chat
cerebro agents chat <session-id>
> "What are the most critical security issues?"
> "Show me attack paths from GitHub to production"
> "Test SOC2 controls"
```

## Examples

**Investigation**
```
> "What permissions did user@company.com have on December 1st?"
Agent: [Uses forensic_replay] → Reconstructs historical state

> "Calculate blast radius if serviceaccount@prod is compromised"
Agent: [Uses calculate_blast_radius] → 247 reachable resources
```

**Compliance**
```
> "Test all SOC2 controls"
Agent: [Uses test_compliance_control] → 89% compliance, 4 gaps

> "Generate evidence bundle for Q4 audit"
Agent: [Uses build_evidence_bundle] → Cryptographically-signed bundle
```

## Performance

Benchmarked with 50,000+ resources across 500+ principals:

- Collection: 10,000 AWS resources in <5 minutes
- Rule Evaluation: 15 rules × 1,000 resources in <30 seconds
- Identity Correlation: 500 principals in <10 seconds
- Temporal Queries: 90 days of access patterns in <2 seconds

## Development

```bash
# Development
make dev           # Start API with hot reload
make test          # Run tests
make lint          # Type checking

# Database
make db-migrate    # Run migrations
make db-reset      # Reset database

# Docker
make docker-up     # Start services
make docker-down   # Stop services
```

### Project Structure

```
cerebro/
├── src/cerebro/
│   ├── agents/         # AI agent system
│   ├── api/            # FastAPI REST API
│   ├── cli/            # Command-line interface
│   ├── collectors/     # Configuration collection
│   ├── core/           # Database models
│   ├── findings/       # Finding management
│   ├── providers/      # Cloud/SaaS integrations
│   ├── query/          # SQL engine
│   └── rules/          # CEL rule engine
├── docs/               # Documentation
├── tests/              # Test suite
└── migrations/         # Database migrations
```

## Documentation

- [Quickstart Guide](docs/QUICKSTART.md)
- [API Reference](docs/API.md)
- [AI Agents](docs/agents/README.md)
- [SQL Query Engine](docs/QUERY_ENGINE.md)
- [Database Schema](docs/DATABASE_SCHEMA.md)
- [Development Guide](docs/DEVELOPMENT.md)
- [Deployment Guide](docs/DEPLOYMENT.md)

## License

Apache 2.0 - See [LICENSE](LICENSE)

## Links

- GitHub: https://github.com/WriterInternal/cerebro
- Issues: https://github.com/WriterInternal/cerebro/issues