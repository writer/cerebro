# Cerebro Platform Development Plan

## Executive Summary

Cerebro is Writer's internal security data platform with **~80,000 lines of Python** across **460 modules**. It provides unified security posture management, compliance automation, and AI-powered investigation capabilities. This document outlines the roadmap for building out Cerebro as a comprehensive enterprise security platform.

---

## Current State Assessment

### Core Capabilities (Implemented)

| Domain | Status | Components |
|--------|--------|------------|
| **Data Ingestion** | ✅ Mature | AWS, GCP, Azure, GitHub, Okta, M365, Workspace, Kubernetes providers |
| **Identity & Access** | ✅ Mature | IAM edge analysis, identity stitching, privilege detection |
| **Compliance** | ✅ Mature | SOC2, ISO27001 frameworks, evidence collection, policy management |
| **Findings Pipeline** | ✅ Mature | CEL rule engine, severity scoring, remediation tracking |
| **Agent Runtime** | ✅ Mature | Tool execution, approval workflows, memory, telemetry |
| **API Layer** | ✅ Mature | FastAPI REST, versioned OpenAPI, rate limiting |
| **Analytics** | ✅ Functional | Snowflake warehouse, SQL/graph queries, dashboards |
| **Vendor/Customer Management** | ✅ Functional | Risk scoring, lifecycle tracking, evidence metadata |

### Architecture Strengths

1. **Append-only audit trail** - Immutable data model for compliance
2. **CEL-based policy engine** - Flexible, portable rule definitions
3. **Multi-provider abstraction** - Consistent interface across cloud/SaaS
4. **Agent autonomy controls** - Graduated approval workflows with telemetry
5. **Dual SDK support** - TypeScript + Python with shared primitives

### Technical Debt & Gaps

| Area | Issue | Priority |
|------|-------|----------|
| Type Coverage | ~800+ mypy warnings (mostly missing annotations in older modules) | Medium |
| Test Coverage | Unit tests solid; integration/E2E coverage sparse | High |
| Documentation | API docs good; architecture/runbook docs need updates | Medium |
| Observability | Prometheus metrics exist; distributed tracing incomplete | Medium |
| Error Handling | Inconsistent exception hierarchy across providers | Low |

---

## Phase 1: Foundation Hardening (Current → Q1)

### 1.1 Code Quality & Reliability

- [ ] **Complete type annotations** - Target 100% coverage for public APIs
- [ ] **Standardize exception hierarchy** - `CerebroError` base with provider-specific subclasses
- [ ] **Add integration test suite** - Provider mocks, E2E workflows, contract tests
- [ ] **Implement structured logging** - JSON logs with correlation IDs across services
- [ ] **Add OpenTelemetry tracing** - Distributed traces for API → Worker → Provider flows

### 1.2 Security Hardening

- [ ] **API key rotation mechanism** - Automated rotation with zero-downtime
- [ ] **Secrets scanning** - Pre-commit hooks, CI pipeline integration
- [ ] **RBAC enhancements** - Fine-grained scopes beyond current admin/read levels
- [ ] **Audit log immutability** - Cryptographic chaining for tamper evidence
- [ ] **Rate limiting per scope** - Separate limits for read vs. write operations

### 1.3 Operational Excellence

- [ ] **Health check endpoints** - Deep checks for DB, Redis, providers
- [ ] **Graceful degradation** - Circuit breakers for external dependencies
- [ ] **Runbook automation** - Self-healing for common failure modes
- [ ] **Capacity planning** - Load testing, resource projections

---

## Phase 2: Platform Expansion (Q1-Q2)

### 2.1 Provider Ecosystem

| Provider | Status | Priority | Notes |
|----------|--------|----------|-------|
| AWS | ✅ Complete | - | EC2, S3, IAM, CloudTrail, GuardDuty |
| GCP | ✅ Complete | - | Compute, IAM, Cloud Audit Logs |
| Azure | ⚠️ Partial | High | Expand beyond current scope |
| GitHub | ✅ Complete | - | Repos, Actions, GHAS findings |
| Okta | ✅ Complete | - | Users, groups, apps, policies |
| M365 | ⚠️ Partial | High | Expand Entra ID, Defender coverage |
| **Slack Enterprise** | ❌ Missing | High | Audit logs, DLP events |
| **Salesforce** | ❌ Missing | Medium | User access, data exposure |
| **Datadog** | ❌ Missing | Medium | Security signals integration |
| **CrowdStrike** | ❌ Missing | High | EDR findings, threat intel |
| **SentinelOne** | ⚠️ Partial | Medium | Expand beyond current scope |
| **Snyk** | ❌ Missing | Medium | Vulnerability findings |
| **Wiz** | ❌ Missing | High | Cloud security posture |

### 2.2 Compliance Frameworks

| Framework | Status | Priority |
|-----------|--------|----------|
| SOC 2 | ✅ Complete | - |
| ISO 27001 | ✅ Complete | - |
| **NIST CSF 2.0** | ❌ Missing | High |
| **CIS Controls v8** | ❌ Missing | High |
| **PCI DSS 4.0** | ❌ Missing | Medium |
| **HIPAA** | ❌ Missing | Medium |
| **FedRAMP** | ❌ Missing | Low |
| **GDPR** | ⚠️ Partial | Medium |

### 2.3 Analytics & Reporting

- [ ] **Executive dashboards** - Board-ready compliance scorecards
- [ ] **Trend analysis** - Risk posture over time, drift detection
- [ ] **Custom report builder** - Drag-and-drop widget configuration
- [ ] **Scheduled exports** - PDF/Excel reports on cadence
- [ ] **Benchmark comparisons** - Industry/peer group positioning

---

## Phase 3: AI-Powered Security (Q2-Q3)

### 3.1 Agent Capabilities

| Capability | Status | Priority | Description |
|------------|--------|----------|-------------|
| Investigation assist | ✅ Functional | - | Query execution, context retrieval |
| Remediation suggestions | ⚠️ Basic | High | Expand playbook coverage |
| **Auto-triage** | ❌ Missing | High | ML-based severity/priority scoring |
| **Root cause analysis** | ❌ Missing | High | Graph traversal for blast radius |
| **Threat hunting** | ❌ Missing | Medium | Proactive anomaly detection |
| **Incident response** | ⚠️ Basic | High | Containment action execution |
| **Policy generation** | ❌ Missing | Medium | CEL rules from natural language |

### 3.2 Training & Evaluation (from TODO.md)

- [ ] **Benchmark suites** - Convert playbooks to reproducible tests
- [ ] **Evaluation pipelines** - CI scoring for agent changes
- [ ] **Training data capture** - Investigation transcripts, tool telemetry
- [ ] **Fine-tuning corpora** - Cerebro-specific model adaptation
- [ ] **Security gym** - Containerized attack/defense scenarios

### 3.3 Autonomy Controls

- [ ] **Confidence scoring** - Per-action confidence with thresholds
- [ ] **Graduated autonomy** - Levels: suggest → execute-with-approval → auto-execute
- [ ] **Blast radius limits** - Prevent actions affecting >N resources
- [ ] **Rollback capabilities** - Undo remediation actions
- [ ] **Audit trails** - Complete lineage for autonomous actions

---

## Phase 4: Enterprise Features (Q3-Q4)

### 4.1 Multi-Tenancy

- [ ] **Organization hierarchy** - Parent/child org relationships
- [ ] **Data isolation** - Schema-level or row-level security
- [ ] **Cross-org analytics** - Aggregate views for MSPs
- [ ] **White-labeling** - Custom branding per tenant

### 4.2 Integrations

- [ ] **SIEM integration** - Splunk, Elastic, Chronicle export
- [ ] **SOAR integration** - Cortex XSOAR, Tines playbooks
- [ ] **Ticketing** - Jira, ServiceNow, PagerDuty bi-directional sync
- [ ] **Chat** - Slack/Teams bot for alerts and queries
- [ ] **Webhook framework** - Generic outbound events

### 4.3 Workflow Automation

- [ ] **Custom playbooks** - Visual workflow builder
- [ ] **Scheduled scans** - Configurable collection cadence
- [ ] **Alert rules** - Condition-based notifications
- [ ] **Approval chains** - Multi-level review workflows
- [ ] **SLA tracking** - Response time metrics and escalation

---

## Phase 5: Scale & Performance (Ongoing)

### 5.1 Data Layer

- [ ] **Partitioning strategy** - Time-based partitions for findings/configs
- [ ] **Archive policies** - Cold storage for historical data
- [ ] **Query optimization** - Materialized views, query caching
- [ ] **Read replicas** - Geographic distribution

### 5.2 Compute Layer

- [ ] **Horizontal scaling** - Stateless workers with queue-based distribution
- [ ] **Provider parallelization** - Concurrent collection across accounts
- [ ] **Rate limit management** - Per-provider adaptive throttling
- [ ] **Resource pooling** - Connection/session reuse

### 5.3 Observability

- [ ] **SLI/SLO framework** - Defined targets with burn-rate alerts
- [ ] **Cost attribution** - Per-org resource usage tracking
- [ ] **Anomaly detection** - Automatic baseline deviation alerts
- [ ] **Capacity forecasting** - Growth projections from usage trends

---

## Immediate Action Items (Next 2 Weeks)

### Priority 1: Critical Path

1. **Add integration tests for providers** - Mock-based tests for AWS, GCP, Okta
2. **Implement CrowdStrike provider** - EDR findings integration
3. **Add NIST CSF 2.0 framework** - Control mappings and evidence collection
4. **Enhance agent remediation** - Expand action catalog with rollback

### Priority 2: Quick Wins

1. **API key usage tracking** - CloudWatch/Redis metrics integration
2. **Executive dashboard endpoint** - Aggregate compliance scores
3. **Slack Enterprise provider** - Audit log ingestion
4. **Health check improvements** - Deep dependency checks

### Priority 3: Technical Debt

1. **Type annotation pass** - Focus on core/ and api/ modules
2. **Exception standardization** - Define hierarchy, update providers
3. **Logging consistency** - Structured JSON with trace IDs
4. **Documentation refresh** - Architecture diagrams, runbooks

---

## Success Metrics

| Metric | Current | Q2 Target | Q4 Target |
|--------|---------|-----------|-----------|
| Provider count | 10 | 15 | 20 |
| Framework coverage | 2 | 5 | 8 |
| Test coverage (unit) | ~60% | 80% | 90% |
| Test coverage (E2E) | ~10% | 40% | 60% |
| Agent action catalog | ~20 | 40 | 80 |
| P95 API latency | TBD | <500ms | <200ms |
| Collection freshness | 24h | 6h | 1h |

---

## Resource Requirements

### Engineering

- **Backend** - 2-3 engineers for provider expansion, compliance frameworks
- **Platform** - 1 engineer for infrastructure, scaling, observability
- **ML/AI** - 1 engineer for agent capabilities, training pipelines

### Infrastructure

- **Compute** - Additional worker capacity for parallel collection
- **Storage** - Snowflake warehouse expansion for analytics
- **External APIs** - Provider API quotas and rate limits

---

## Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Provider API changes | High | Medium | Version pinning, change detection |
| Data volume growth | Medium | High | Archival policies, partitioning |
| Agent hallucinations | High | Medium | Confidence thresholds, human review |
| Compliance drift | Medium | Medium | Automated evidence collection |
| Key personnel dependency | High | Medium | Documentation, knowledge sharing |

---

## Appendix: Module Inventory

### Core Modules (~15k LOC)
- `core/` - Database, config, models, repositories
- `api/` - FastAPI routers, auth, schemas

### Domain Modules (~25k LOC)
- `agents/` - Runtime, tools, memory, review queue
- `compliance/` - Frameworks, evidence, policies
- `findings/` - Evaluator, producers, pipelines

### Integration Modules (~30k LOC)
- `providers/` - Cloud and SaaS adapters
- `integrations/` - External service connectors
- `telemetry/` - Ingestion pipelines

### Supporting Modules (~10k LOC)
- `analytics/` - Dashboard, SQL dialect
- `query/` - Table definitions, graph queries
- `tasks/` - Celery workers, scheduled jobs

---

*Last updated: January 2026*
*Owner: Security Platform Team*
