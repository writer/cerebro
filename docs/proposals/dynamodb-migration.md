# DynamoDB Migration Design Document

**Status:** Draft  
**Author:** Engineering  
**Date:** 2024-12-10  
**Reviewers:** InfoSec Team, Platform Engineering, SRE  
**Last Updated:** 2024-12-10

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current State Analysis](#1-current-state-analysis)
3. [DynamoDB Data Model Design](#2-dynamodb-data-model-design)
4. [Patterns Requiring Alternative Solutions](#3-patterns-requiring-alternative-solutions)
5. [Infrastructure Changes](#4-infrastructure-changes)
6. [Application Layer Changes](#5-application-layer-changes)
7. [Migration Strategy](#6-migration-strategy)
8. [Files Requiring Modification](#7-files-requiring-modification)
9. [Testing Strategy](#8-testing-strategy)
10. [Security Considerations](#9-security-considerations)
11. [Risks and Mitigations](#10-risks-and-mitigations)
12. [Cost Analysis](#11-cost-analysis)
13. [Success Criteria](#12-success-criteria)
14. [Open Questions](#13-open-questions)
15. [Appendices](#appendices)

---

## Executive Summary

This document outlines the migration strategy from PostgreSQL to Amazon DynamoDB for the Cerebro security platform. The migration affects ~40 SQLAlchemy models, ~130 files with database queries, and infrastructure across AWS and GCP.

### Why DynamoDB?

| Factor | PostgreSQL (Current) | DynamoDB (Proposed) |
|--------|---------------------|---------------------|
| Scalability | Vertical (instance size) | Horizontal (automatic) |
| Operational Overhead | High (backups, replicas, patching) | Low (fully managed) |
| Cost Model | Instance-based (always on) | On-demand or provisioned |
| Latency | ~5-20ms typical | ~1-10ms typical |
| Global Distribution | Complex (read replicas) | Native (Global Tables) |
| Schema Flexibility | Rigid (migrations required) | Flexible (schemaless) |

### Scope of Changes

- **40+ database models** requiring redesign
- **130+ files** with database queries requiring rewrite
- **2 infrastructure modules** (AWS RDS, GCP Cloud SQL) to replace
- **37 Alembic migrations** to deprecate
- **Estimated timeline**: 9-12 weeks

### Key Decisions Required

1. **GCP Support**: Continue with GCP (requires Firestore) or AWS-only?
2. **Data Retention**: TTL policies for audit logs and config snapshots?
3. **Search Strategy**: OpenSearch integration or denormalization?
4. **Consistency Model**: Where is strong consistency required?

---

## 1. Current State Analysis

### 1.1 Database Schema Overview

The current PostgreSQL schema consists of **47 tables** organized into the following entity groups:

#### Core Entities (src/cerebro/core/models.py) - 22 Tables

| Table | Primary Key | Columns | Key Relationships | Estimated Volume | Growth Rate |
|-------|-------------|---------|-------------------|------------------|-------------|
| `orgs` | `org_id` (UUID) | 4 | Parent of all tenant data | ~100s | Low |
| `accounts` | `account_id` (UUID) | 5 | FK → orgs | ~1,000s | Medium |
| `principals` | `principal_id` (UUID) | 8 | FK → accounts | ~100,000s | High |
| `resources` | `resource_id` (UUID) | 8 | FK → accounts | ~100,000s | High |
| `config_snapshots` | `snapshot_id` (UUID) | 6 | FK → resources | ~10,000,000s | Very High |
| `iam_edges` | `edge_id` (UUID) | 10 | FK → accounts, principals, resources | ~10,000,000s | Very High |
| `findings` | `finding_id` (UUID) | 17 | FK → orgs, accounts, rules, resources, principals | ~100,000s | High |
| `evidence_artifacts` | `artifact_id` (UUID) | 7 | FK → findings | ~500,000s | High |
| `rules` | `rule_id` (UUID) | 15 | FK → policies | ~1,000s | Low |
| `policies` | `policy_id` (UUID) | 6 | FK → orgs | ~100s | Low |
| `suppressions` | `suppression_id` (UUID) | 8 | FK → orgs, rules | ~1,000s | Low |
| `audit_events` | `event_id` (UUID) | 8 | FK → accounts | ~50,000,000s | Very High |
| `slack_webhooks` | `webhook_id` (UUID) | 14 | FK → orgs | ~100s | Low |
| `slack_notifications` | `notification_id` (UUID) | 13 | FK → slack_webhooks, orgs | ~100,000s | Medium |
| `email_configs` | `config_id` (UUID) | 18 | FK → orgs | ~100s | Low |
| `email_notifications` | `notification_id` (UUID) | 15 | FK → email_configs, orgs | ~50,000s | Medium |
| `webhook_configs` | `config_id` (UUID) | 16 | FK → orgs | ~100s | Low |
| `webhook_notifications` | `notification_id` (UUID) | 14 | FK → webhook_configs, orgs | ~50,000s | Medium |
| `identity_clusters` | `cluster_id` (UUID) | 9 | FK → orgs | ~10,000s | Medium |
| `identity_cluster_members` | `member_id` (UUID) | 7 | FK → clusters, principals | ~50,000s | Medium |
| `identity_stitching_logs` | `log_id` (UUID) | 9 | FK → orgs, clusters | ~100,000s | Medium |
| `identity_remediation_actions` | `action_id` (UUID) | 16 | FK → orgs, principals, users | ~10,000s | Medium |

#### Agent Entities (src/cerebro/agents/models.py) - 18 Tables

| Table | Primary Key | Columns | Key Relationships | Estimated Volume |
|-------|-------------|---------|-------------------|------------------|
| `agent_sessions` | `id` (UUID) | 8 | FK → orgs | ~50,000s |
| `agent_messages` | `id` (UUID) | 7 | FK → agent_sessions | ~500,000s |
| `agent_conversation_items` | `id` (UUID) | 4 | FK → agent_sessions | ~1,000,000s |
| `agent_memory_entries` | `id` (UUID) | 16 | FK → orgs, agent_sessions | ~100,000s |
| `tool_invocations` | `id` (UUID) | 17 | FK → agent_sessions | ~200,000s |
| `tool_approvals` | `id` (UUID) | 12 | FK → orgs, tool_invocations | ~10,000s |
| `agent_review_tasks` | `id` (UUID) | 20 | FK → orgs, agent_sessions, messages | ~20,000s |
| `agent_review_notifications` | `id` (UUID) | 8 | FK → orgs, tasks | ~50,000s |
| `agent_review_tickets` | `id` (UUID) | 9 | FK → orgs, tasks | ~10,000s |
| `agent_review_comments` | `id` (UUID) | 7 | FK → tasks | ~30,000s |
| `agent_review_history` | `id` (UUID) | 9 | FK → tasks | ~100,000s |
| `agent_session_context` | `id` (UUID) | 12 | FK → sessions, orgs | ~50,000s |
| `agent_runtime_events` | `id` (UUID) | 6 | FK → orgs, sessions | ~500,000s |
| `agent_self_service_questions` | `id` (UUID) | 13 | FK → orgs, sessions | ~20,000s |
| `agent_self_service_reports` | `id` (UUID) | 8 | FK → orgs | ~1,000s |
| `agent_memory_decay_overrides` | `id` (UUID) | 7 | FK → orgs | ~100s |
| `agent_policy_suggestions` | `id` (UUID) | 9 | FK → orgs | ~5,000s |
| `agent_recommendations` | `id` (UUID) | 14 | FK → sessions, orgs | ~10,000s |

#### Integration Entities - 4 Tables

| Table | Primary Key | Columns | Key Relationships | Estimated Volume |
|-------|-------------|---------|-------------------|------------------|
| `serval_integrations` | `integration_id` (UUID) | 14 | FK → orgs (1:1) | ~100s |
| `integration_sync_state` | `state_id` (UUID) | 7 | Standalone | ~500s |
| `integration_sync_issue_events` | `issue_id` (UUID) | 10 | Standalone | ~10,000s |
| `frontend_observation_events` | `event_id` (UUID) | 9 | FK → orgs, users | ~1,000,000s |

#### User/Auth Entities - 3 Tables

| Table | Primary Key | Columns | Key Relationships | Estimated Volume |
|-------|-------------|---------|-------------------|------------------|
| `users` | `user_id` (UUID) | ~15 | FK → orgs | ~10,000s |
| `refresh_tokens` | `token_id` (UUID) | ~8 | FK → users | ~50,000s |
| `api_keys` | `key_id` (UUID) | ~10 | FK → orgs, users | ~5,000s |

### 1.2 Complete Column Definitions

#### 1.2.1 Organization Table (`orgs`)

```sql
CREATE TABLE orgs (
    org_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR NOT NULL,
    slack_config JSONB,                    -- Slack workspace configuration
    created_at TIMESTAMPTZ DEFAULT now()
);
```

**Security Consideration**: `slack_config` may contain OAuth tokens - requires encryption at rest.

#### 1.2.2 Accounts Table (`accounts`)

```sql
CREATE TABLE accounts (
    account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(org_id) ON DELETE CASCADE,
    provider VARCHAR NOT NULL,              -- 'github', 'google_workspace', 'aws', 'gcp', 'runtime', 'endpoint'
    external_id VARCHAR NOT NULL,           -- Provider-specific account ID
    display_name VARCHAR,
    UNIQUE(org_id, provider, external_id),
    CHECK (provider IN ('github','google_workspace','aws','gcp','runtime','endpoint'))
);
```

#### 1.2.3 Principals Table (`principals`)

```sql
CREATE TABLE principals (
    principal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    provider VARCHAR NOT NULL,
    principal_type VARCHAR NOT NULL,        -- 'user', 'group', 'service_account', 'app', 'role'
    external_id VARCHAR NOT NULL,
    email VARCHAR,
    display_name VARCHAR,
    is_human BOOLEAN,
    UNIQUE(account_id, provider, external_id),
    CHECK (principal_type IN ('user','group','service_account','app','role'))
);
```

#### 1.2.4 Resources Table (`resources`)

```sql
CREATE TABLE resources (
    resource_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    provider VARCHAR NOT NULL,
    resource_type VARCHAR NOT NULL,
    external_id VARCHAR NOT NULL,
    name VARCHAR,
    parent_external_id VARCHAR,
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(account_id, provider, resource_type, external_id)
);
```

#### 1.2.5 Config Snapshots Table (`config_snapshots`)

```sql
CREATE TABLE config_snapshots (
    snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id UUID NOT NULL REFERENCES resources(resource_id) ON DELETE CASCADE,
    captured_at TIMESTAMPTZ NOT NULL,
    config_sha BYTEA NOT NULL,              -- SHA-256 hash for deduplication
    normalized_config JSONB NOT NULL,       -- Full configuration document
    collector_version VARCHAR NOT NULL,
    UNIQUE(resource_id, config_sha)
);

CREATE INDEX ix_config_snapshots_resource_captured ON config_snapshots(resource_id, captured_at);
CREATE INDEX ix_config_snapshots_normalized_config ON config_snapshots USING GIN(normalized_config);
```

**Security Consideration**: `normalized_config` contains cloud resource configurations - may include sensitive settings.

#### 1.2.6 IAM Edges Table (`iam_edges`)

```sql
CREATE TABLE iam_edges (
    edge_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    provider VARCHAR NOT NULL,
    principal_id UUID NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    resource_id UUID REFERENCES resources(resource_id) ON DELETE CASCADE,
    permission VARCHAR NOT NULL,
    via VARCHAR,                            -- How permission was granted (role, group, direct)
    effective_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE(account_id, provider, principal_id, resource_id, permission, effective_at, via)
);

CREATE INDEX ix_iam_edges_principal ON iam_edges(principal_id);
CREATE INDEX ix_iam_edges_resource ON iam_edges(resource_id);
CREATE INDEX ix_iam_edges_is_admin ON iam_edges(is_admin);
CREATE INDEX ix_iam_edges_effective_at ON iam_edges(effective_at);
```

#### 1.2.7 Findings Table (`findings`)

```sql
CREATE TABLE findings (
    finding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(org_id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    provider VARCHAR NOT NULL,
    rule_id UUID NOT NULL REFERENCES rules(rule_id),
    rule_version INTEGER NOT NULL,
    resource_id UUID REFERENCES resources(resource_id),
    principal_id UUID REFERENCES principals(principal_id),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    status VARCHAR NOT NULL,                -- 'open', 'suppressed', 'accepted_risk', 'fixed'
    severity VARCHAR NOT NULL,              -- 'critical', 'high', 'medium', 'low', 'info'
    fingerprint VARCHAR NOT NULL,           -- Unique identifier for deduplication
    title VARCHAR NOT NULL,
    summary TEXT,
    evidence JSONB,                         -- Supporting evidence for the finding
    UNIQUE(org_id, fingerprint),
    CHECK (status IN ('open','suppressed','accepted_risk','fixed'))
);

CREATE INDEX ix_findings_status ON findings(status);
CREATE INDEX ix_findings_severity ON findings(severity);
CREATE INDEX ix_findings_last_seen ON findings(last_seen);
```

#### 1.2.8 Rules Table (`rules`)

```sql
CREATE TABLE rules (
    rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID REFERENCES policies(policy_id) ON DELETE SET NULL,
    name VARCHAR NOT NULL,
    description TEXT,
    provider VARCHAR[] NOT NULL,            -- Array of applicable providers
    resource_types VARCHAR[],               -- Array of applicable resource types
    expression_lang VARCHAR NOT NULL,       -- 'sql', 'rego', 'cel'
    expression TEXT NOT NULL,               -- The rule expression
    severity VARCHAR NOT NULL,
    cwe VARCHAR[],                          -- CWE identifiers
    cis VARCHAR[],                          -- CIS benchmark mappings
    nist_800_53 VARCHAR[],                  -- NIST 800-53 control mappings
    mitre_attack VARCHAR[],                 -- MITRE ATT&CK mappings
    version INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT now(),
    CHECK (expression_lang IN ('sql','rego','cel')),
    CHECK (severity IN ('critical','high','medium','low','info'))
);

CREATE INDEX ix_rules_is_active ON rules(is_active);
CREATE INDEX ix_rules_provider ON rules USING GIN(provider);
CREATE INDEX ix_rules_resource_types ON rules USING GIN(resource_types);
```

#### 1.2.9 Audit Events Table (`audit_events`)

```sql
CREATE TABLE audit_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    provider VARCHAR NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    actor_external_id VARCHAR,
    action VARCHAR NOT NULL,
    resource_external_id VARCHAR,
    raw JSONB NOT NULL,                     -- Raw event from provider
);

CREATE INDEX ix_audit_events_occurred_at ON audit_events(occurred_at);
CREATE INDEX ix_audit_events_provider_action ON audit_events(provider, action);
CREATE INDEX ix_audit_events_raw ON audit_events USING GIN(raw);
```

**Security Consideration**: `raw` contains complete audit logs which may include PII, IP addresses, and sensitive actions.

#### 1.2.10 Encrypted Fields (Notification Tables)

Several tables contain envelope-encrypted sensitive data:

```sql
-- slack_webhooks
webhook_url BYTEA,          -- AES-256-GCM encrypted webhook URL
webhook_url_dek BYTEA,      -- Encrypted DEK (wrapped by KMS)

-- email_configs
smtp_password BYTEA,        -- AES-256-GCM encrypted SMTP password
smtp_password_dek BYTEA,    -- Encrypted DEK

-- webhook_configs
hmac_secret BYTEA,          -- AES-256-GCM encrypted HMAC secret
hmac_secret_dek BYTEA,      -- Encrypted DEK

-- serval_integrations
encrypted_client_id BYTEA,
encrypted_client_id_dek BYTEA,
encrypted_client_secret BYTEA,
encrypted_client_secret_dek BYTEA,
```

**Encryption Pattern**: Uses envelope encryption with AWS KMS or GCP Cloud KMS:
1. Generate random DEK (Data Encryption Key)
2. Encrypt data with DEK using AES-256-GCM
3. Encrypt DEK with KMS KEK (Key Encryption Key)
4. Store both encrypted data and encrypted DEK

### 1.3 Current Query Patterns

Analysis of ~130 files reveals the following access patterns:

#### High-Frequency Patterns
1. **Get by ID within Org**: `SELECT * FROM findings WHERE finding_id = ? AND org_id = ?`
2. **List by Org with Filters**: `SELECT * FROM findings WHERE org_id = ? AND status = ? ORDER BY created_at DESC LIMIT ?`
3. **Get by External ID**: `SELECT * FROM principals WHERE account_id = ? AND external_id = ?`
4. **Time-range Queries**: `SELECT * FROM audit_events WHERE account_id = ? AND occurred_at BETWEEN ? AND ?`
5. **Aggregate Queries**: `SELECT severity, COUNT(*) FROM findings WHERE org_id = ? GROUP BY severity`

#### Complex Patterns (Require Redesign)
1. **JOINs**: Finding → Rule → Policy (for compliance mapping)
2. **GIN Index Searches**: JSONB queries on `normalized_config`, `evidence`, `raw`
3. **Multi-table Aggregations**: MTTR calculations across findings
4. **Relationship Traversals**: Account → Principals → IAM Edges → Resources

### 1.4 PostgreSQL-Specific Features in Use

| Feature | Usage Location | DynamoDB Alternative | Migration Complexity |
|---------|----------------|---------------------|----------------------|
| `JSONB` with GIN indexes | config_snapshots, audit_events, evidence | Denormalize or use OpenSearch | High |
| `ARRAY` types | rules.provider, rules.cwe, to_emails | Store as JSON List (L type) | Low |
| `UUID` with `gen_random_uuid()` | All 47 tables | Client-side UUID generation (uuid4) | Low |
| Foreign Key Constraints | 60+ relationships | Application-level enforcement | Medium |
| `CHECK` constraints | 15+ enum validations | Application-level validation + GSI sparse indexes | Medium |
| `UNIQUE` constraints | 25+ composite keys | Conditional writes + GSI uniqueness | Medium |
| Transactions | Multi-table writes in 40+ locations | DynamoDB Transactions (25 item limit) | High |
| `CASCADE DELETE` | All FK relationships | DynamoDB Streams + Lambda cleanup | High |
| `ON UPDATE` triggers | updated_at columns | Application-level timestamp management | Low |
| Window Functions | Analytics queries | Pre-computed aggregates or Athena | High |
| CTEs (WITH clause) | Complex reports | Multiple queries + application joins | High |

### 1.5 Current Index Analysis

#### B-Tree Indexes (Standard)
```sql
-- 45+ B-tree indexes across all tables
ix_findings_status ON findings(status)
ix_findings_severity ON findings(severity)
ix_findings_last_seen ON findings(last_seen)
ix_iam_edges_principal ON iam_edges(principal_id)
ix_iam_edges_resource ON iam_edges(resource_id)
ix_iam_edges_is_admin ON iam_edges(is_admin)
ix_audit_events_occurred_at ON audit_events(occurred_at)
ix_agent_sessions_org ON agent_sessions(org_id)
ix_agent_sessions_created ON agent_sessions(created_at)
-- ... and 35+ more
```

#### GIN Indexes (JSON/Array Search)
```sql
-- 8 GIN indexes requiring OpenSearch or denormalization
ix_config_snapshots_normalized_config ON config_snapshots USING GIN(normalized_config)
ix_audit_events_raw ON audit_events USING GIN(raw)
ix_rules_provider ON rules USING GIN(provider)
ix_rules_resource_types ON rules USING GIN(resource_types)
-- These support queries like:
-- SELECT * FROM config_snapshots WHERE normalized_config @> '{"encryption": {"enabled": false}}'
-- SELECT * FROM audit_events WHERE raw @> '{"actor": {"email": "user@example.com"}}'
```

#### Composite Indexes
```sql
-- 12 composite indexes
ix_config_snapshots_resource_captured ON config_snapshots(resource_id, captured_at)
ix_audit_events_provider_action ON audit_events(provider, action)
ix_iam_edges_account_permission ON iam_edges(account_id, permission)
```

### 1.6 Relationship Cardinality Analysis

```
Organization (1) ─────┬───── (N) Account
                      ├───── (N) Policy
                      ├───── (N) Finding
                      ├───── (N) Suppression
                      ├───── (N) SlackWebhook
                      ├───── (N) EmailConfig
                      ├───── (N) WebhookConfig
                      ├───── (N) AgentSession
                      ├───── (N) IdentityCluster
                      ├───── (1) ServalIntegration
                      └───── (N) User

Account (1) ──────────┬───── (N) Principal (~100-10K per account)
                      ├───── (N) Resource (~100-100K per account)
                      ├───── (N) IAMEdge (~1K-1M per account)
                      ├───── (N) AuditEvent (~10K-10M per account)
                      └───── (N) Finding

Principal (1) ────────┬───── (N) IAMEdge
                      ├───── (N) Finding
                      └───── (N) IdentityClusterMember

Resource (1) ─────────┬───── (N) ConfigSnapshot (~1-1K per resource)
                      ├───── (N) IAMEdge
                      └───── (N) Finding

AgentSession (1) ─────┬───── (N) AgentMessage (~1-500 per session)
                      ├───── (N) ToolInvocation (~1-100 per session)
                      ├───── (N) AgentConversationItem (~1-1K per session)
                      └───── (N) AgentMemoryEntry
```

### 1.7 Data Volume Projections (12-month)

| Table | Current | 6 Months | 12 Months | Storage (12mo) |
|-------|---------|----------|-----------|----------------|
| audit_events | 50M | 150M | 300M | ~500 GB |
| config_snapshots | 10M | 30M | 60M | ~200 GB |
| iam_edges | 10M | 25M | 50M | ~50 GB |
| agent_conversation_items | 1M | 5M | 15M | ~30 GB |
| frontend_observation_events | 1M | 5M | 15M | ~20 GB |
| findings | 100K | 300K | 600K | ~5 GB |
| All other tables | - | - | - | ~10 GB |
| **Total** | **~72M** | **~215M** | **~440M** | **~815 GB** |

---

## 2. DynamoDB Data Model Design

### 2.1 Design Approach: Hybrid Single-Table + Domain Tables

Given the complexity and scale, we recommend a **hybrid approach**:

- **Single-table design** for frequently-joined entities (Org → Account → Principal/Resource)
- **Separate tables** for high-volume append-only data (audit_events, config_snapshots)
- **Separate tables** for distinct domains (agents, notifications)

### 2.2 Table Definitions

#### Table 1: `cerebro-core` (Single-Table Design)

**Purpose**: Core security entities with frequent cross-entity queries

```
Primary Key: PK (String), SK (String)
GSI1: GSI1PK (String), GSI1SK (String)
GSI2: GSI2PK (String), GSI2SK (String)
GSI3: GSI3PK (String), GSI3SK (String)
```

| Entity | PK | SK | GSI1PK | GSI1SK | GSI2PK | GSI2SK |
|--------|----|----|--------|--------|--------|--------|
| Organization | `ORG#<org_id>` | `META` | - | - | - | - |
| Account | `ORG#<org_id>` | `ACCT#<account_id>` | `ACCT#<account_id>` | `META` | `PROVIDER#<provider>` | `EXT#<external_id>` |
| Principal | `ACCT#<account_id>` | `PRIN#<principal_id>` | `ORG#<org_id>` | `PRIN#<principal_id>` | `PROVIDER#<provider>` | `EXT#<external_id>` |
| Resource | `ACCT#<account_id>` | `RES#<resource_id>` | `ORG#<org_id>` | `RES#<resource_id>` | `RESTYPE#<type>` | `EXT#<external_id>` |
| IAMEdge | `PRIN#<principal_id>` | `EDGE#<edge_id>` | `RES#<resource_id>` | `EDGE#<edge_id>` | `ACCT#<account_id>` | `PERM#<permission>` |
| Finding | `ORG#<org_id>` | `FIND#<finding_id>` | `ACCT#<account_id>` | `FIND#<finding_id>` | `STATUS#<status>` | `SEV#<severity>#<created>` |
| Rule | `ORG#<org_id>` | `RULE#<rule_id>` | `POLICY#<policy_id>` | `RULE#<rule_id>` | - | - |
| Policy | `ORG#<org_id>` | `POLICY#<policy_id>` | - | - | - | - |
| Suppression | `ORG#<org_id>` | `SUPP#<suppression_id>` | `RULE#<rule_id>` | `SUPP#<suppression_id>` | - | - |

#### Table 2: `cerebro-audit` (Time-Series)

**Purpose**: High-volume append-only audit events

```
Primary Key: PK (String), SK (String)
GSI1: GSI1PK (String), GSI1SK (String)
TTL: expires_at (Number) - optional for retention
```

| Entity | PK | SK | GSI1PK | GSI1SK |
|--------|----|----|--------|--------|
| AuditEvent | `ACCT#<account_id>` | `EVENT#<timestamp>#<event_id>` | `PROVIDER#<provider>#ACTION#<action>` | `<timestamp>` |
| ConfigSnapshot | `RES#<resource_id>` | `SNAP#<timestamp>#<snapshot_id>` | `ACCT#<account_id>` | `SNAP#<timestamp>` |

#### Table 3: `cerebro-agents`

**Purpose**: Agent sessions and related data

```
Primary Key: PK (String), SK (String)
GSI1: GSI1PK (String), GSI1SK (String)
```

| Entity | PK | SK | GSI1PK | GSI1SK |
|--------|----|----|--------|--------|
| AgentSession | `ORG#<org_id>` | `SESSION#<session_id>` | `USER#<created_by>` | `SESSION#<created_at>` |
| AgentMessage | `SESSION#<session_id>` | `MSG#<timestamp>#<message_id>` | - | - |
| ToolInvocation | `SESSION#<session_id>` | `TOOL#<timestamp>#<invocation_id>` | `ORG#<org_id>` | `TOOL#<tool_name>#<timestamp>` |
| AgentMemoryEntry | `ORG#<org_id>` | `MEM#<entry_id>` | `SESSION#<session_id>` | `MEM#<created_at>` |
| ReviewTask | `ORG#<org_id>` | `REVIEW#<task_id>` | `STATUS#<status>` | `REVIEW#<created_at>` |

#### Table 4: `cerebro-notifications`

**Purpose**: Notification configs and delivery logs

```
Primary Key: PK (String), SK (String)
GSI1: GSI1PK (String), GSI1SK (String)
```

| Entity | PK | SK | GSI1PK | GSI1SK |
|--------|----|----|--------|--------|
| SlackWebhook | `ORG#<org_id>` | `SLACK#<webhook_id>` | - | - |
| SlackNotification | `WEBHOOK#<webhook_id>` | `NOTIF#<timestamp>#<id>` | `ORG#<org_id>` | `SLACKNOTIF#<timestamp>` |
| EmailConfig | `ORG#<org_id>` | `EMAIL#<config_id>` | - | - |
| WebhookConfig | `ORG#<org_id>` | `WEBHOOK#<config_id>` | - | - |

### 2.3 Access Pattern Coverage

| Access Pattern | Table | Key Condition | Filter |
|----------------|-------|---------------|--------|
| Get org by ID | cerebro-core | PK=`ORG#<id>`, SK=`META` | - |
| List accounts for org | cerebro-core | PK=`ORG#<id>`, SK begins_with `ACCT#` | - |
| Get account by provider+external_id | cerebro-core | GSI2: PK=`PROVIDER#<p>`, SK=`EXT#<id>` | - |
| List principals for account | cerebro-core | PK=`ACCT#<id>`, SK begins_with `PRIN#` | - |
| List findings by org+status | cerebro-core | GSI2: PK=`STATUS#<s>`, SK begins_with `SEV#` | Filter org_id |
| Get audit events by time range | cerebro-audit | PK=`ACCT#<id>`, SK between `EVENT#<start>` and `EVENT#<end>` | - |
| List sessions for org | cerebro-agents | PK=`ORG#<id>`, SK begins_with `SESSION#` | - |
| Get messages for session | cerebro-agents | PK=`SESSION#<id>`, SK begins_with `MSG#` | - |

---

## 3. Patterns Requiring Alternative Solutions

### 3.1 Full-Text Search on JSON Fields

**Current**: GIN indexes on `normalized_config`, `evidence`, `raw` fields

**DynamoDB Solution Options**:
1. **Amazon OpenSearch** - Stream DynamoDB to OpenSearch for complex queries
2. **Denormalization** - Extract searchable fields to top-level attributes
3. **Application-side filtering** - For low-volume queries

**Recommendation**: OpenSearch integration for config_snapshots and audit_events

### 3.2 Complex Aggregations

**Current**: 
```sql
SELECT severity, COUNT(*) FROM findings WHERE org_id = ? GROUP BY severity
```

**DynamoDB Solution Options**:
1. **Materialized counters** - Maintain counter items updated on writes
2. **DynamoDB Streams + Lambda** - Process changes and update aggregates
3. **Scan with application aggregation** - For infrequent queries

**Recommendation**: Materialized counters with DynamoDB Streams

### 3.3 Multi-Entity Transactions

**Current**: SQLAlchemy session with multiple inserts/updates

**DynamoDB Constraints**:
- TransactWriteItems: max 25 items, 4MB total
- All items must be in same region

**Recommendation**: 
- Use DynamoDB Transactions for critical consistency (findings + evidence)
- Accept eventual consistency for audit/logging data

---

## 4. Infrastructure Changes

### 4.1 AWS Infrastructure (Pulumi)

Replace `infra/aws/database.py` (RDS) with DynamoDB tables:

```python
# infra/aws/dynamodb.py

def create_dynamodb_tables(
    name: str,
    environment: str,
    kms_key_id: Optional[pulumi.Output[str]] = None,
) -> dict:
    """Create DynamoDB tables for Cerebro."""
    
    tables = {}
    
    # Core table with GSIs
    tables["core"] = aws.dynamodb.Table(
        f"{name}-core",
        name=f"{name}-core-{environment}",
        billing_mode="PAY_PER_REQUEST",  # On-demand for variable workloads
        hash_key="PK",
        range_key="SK",
        attributes=[
            {"name": "PK", "type": "S"},
            {"name": "SK", "type": "S"},
            {"name": "GSI1PK", "type": "S"},
            {"name": "GSI1SK", "type": "S"},
            {"name": "GSI2PK", "type": "S"},
            {"name": "GSI2SK", "type": "S"},
        ],
        global_secondary_indexes=[
            {
                "name": "GSI1",
                "hash_key": "GSI1PK",
                "range_key": "GSI1SK",
                "projection_type": "ALL",
            },
            {
                "name": "GSI2",
                "hash_key": "GSI2PK",
                "range_key": "GSI2SK",
                "projection_type": "ALL",
            },
        ],
        point_in_time_recovery={"enabled": True},
        server_side_encryption={"enabled": True, "kms_key_arn": kms_key_id},
        tags={"Environment": environment},
    )
    
    # Audit table (time-series, with TTL)
    tables["audit"] = aws.dynamodb.Table(
        f"{name}-audit",
        name=f"{name}-audit-{environment}",
        billing_mode="PAY_PER_REQUEST",
        hash_key="PK",
        range_key="SK",
        attributes=[
            {"name": "PK", "type": "S"},
            {"name": "SK", "type": "S"},
            {"name": "GSI1PK", "type": "S"},
            {"name": "GSI1SK", "type": "S"},
        ],
        global_secondary_indexes=[
            {
                "name": "GSI1",
                "hash_key": "GSI1PK",
                "range_key": "GSI1SK",
                "projection_type": "ALL",
            },
        ],
        ttl={"attribute_name": "expires_at", "enabled": True},
        point_in_time_recovery={"enabled": True},
        server_side_encryption={"enabled": True, "kms_key_arn": kms_key_id},
    )
    
    # ... agents and notifications tables similar
    
    return tables
```

### 4.2 GCP Considerations

DynamoDB is AWS-only. Options for GCP:

1. **Firestore** - Document database, similar access patterns
2. **Cloud Spanner** - Relational but globally distributed (expensive)
3. **Bigtable** - Wide-column store for time-series (different model)
4. **Cross-cloud DynamoDB** - Run DynamoDB-compatible (ScyllaDB Alternator)

**Recommendation**: If GCP support required, consider Firestore with a repository abstraction layer.

---

## 5. Application Layer Changes

### 5.1 New Database Module

Replace `src/cerebro/core/database.py`:

```python
# src/cerebro/core/dynamodb.py

import boto3
from typing import Optional
from botocore.config import Config

class DynamoDBClient:
    """DynamoDB client wrapper with table references."""
    
    def __init__(self, region: str = "us-east-1", endpoint_url: Optional[str] = None):
        config = Config(
            retries={"max_attempts": 3, "mode": "adaptive"},
            max_pool_connections=50,
        )
        self._client = boto3.client(
            "dynamodb",
            region_name=region,
            endpoint_url=endpoint_url,  # For local development
            config=config,
        )
        self._resource = boto3.resource(
            "dynamodb",
            region_name=region,
            endpoint_url=endpoint_url,
            config=config,
        )
        
    @property
    def core_table(self):
        return self._resource.Table(settings.dynamodb_core_table)
    
    @property
    def audit_table(self):
        return self._resource.Table(settings.dynamodb_audit_table)
    
    # ... other tables


# Global client instance
_dynamodb_client: Optional[DynamoDBClient] = None

def get_dynamodb() -> DynamoDBClient:
    global _dynamodb_client
    if _dynamodb_client is None:
        _dynamodb_client = DynamoDBClient(
            region=settings.aws_region,
            endpoint_url=settings.dynamodb_endpoint_url,
        )
    return _dynamodb_client
```

### 5.2 Repository Pattern Changes

Example repository migration:

```python
# Before (SQLAlchemy)
class FindingRepository:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def get_by_id(self, org_id: UUID, finding_id: UUID) -> Optional[Finding]:
        stmt = select(Finding).where(
            and_(Finding.org_id == org_id, Finding.finding_id == finding_id)
        )
        return await self.db.scalar(stmt)

# After (DynamoDB)
class FindingRepository:
    def __init__(self, dynamodb: DynamoDBClient):
        self.table = dynamodb.core_table
    
    async def get_by_id(self, org_id: UUID, finding_id: UUID) -> Optional[Finding]:
        response = self.table.get_item(
            Key={
                "PK": f"ORG#{org_id}",
                "SK": f"FIND#{finding_id}",
            }
        )
        item = response.get("Item")
        return Finding.from_dynamodb(item) if item else None
```

### 5.3 Model Changes

Replace SQLAlchemy models with Pydantic + DynamoDB serialization:

```python
# src/cerebro/core/models.py

from pydantic import BaseModel
from typing import Optional, Dict, Any
from uuid import UUID
from datetime import datetime

class Finding(BaseModel):
    finding_id: UUID
    org_id: UUID
    account_id: UUID
    # ... other fields
    
    def to_dynamodb(self) -> Dict[str, Any]:
        """Serialize to DynamoDB item format."""
        return {
            "PK": f"ORG#{self.org_id}",
            "SK": f"FIND#{self.finding_id}",
            "GSI1PK": f"ACCT#{self.account_id}",
            "GSI1SK": f"FIND#{self.finding_id}",
            "GSI2PK": f"STATUS#{self.status}",
            "GSI2SK": f"SEV#{self.severity}#{self.created_at.isoformat()}",
            "finding_id": str(self.finding_id),
            "org_id": str(self.org_id),
            # ... other attributes
        }
    
    @classmethod
    def from_dynamodb(cls, item: Dict[str, Any]) -> "Finding":
        """Deserialize from DynamoDB item."""
        return cls(
            finding_id=UUID(item["finding_id"]),
            org_id=UUID(item["org_id"]),
            # ... other fields
        )
```

---

## 6. Migration Strategy

### 6.1 Phased Approach

| Phase | Scope | Duration | Risk |
|-------|-------|----------|------|
| 1 | Infrastructure + Core tables | 2 weeks | Low |
| 2 | Read path (dual-read from both DBs) | 2 weeks | Low |
| 3 | Write path (dual-write to both DBs) | 2 weeks | Medium |
| 4 | Data migration + validation | 2 weeks | Medium |
| 5 | Cutover + PostgreSQL deprecation | 1 week | High |

### 6.2 Phase 1: Infrastructure

1. Create DynamoDB tables via Pulumi
2. Set up local development with DynamoDB Local
3. Implement new `DynamoDBClient` class
4. Create base repository interfaces

### 6.3 Phase 2: Dual-Read Implementation

1. Implement DynamoDB repositories alongside SQLAlchemy
2. Add feature flag for DynamoDB reads
3. Compare results between both databases
4. Monitor query performance

### 6.4 Phase 3: Dual-Write Implementation

1. Implement write operations to both databases
2. Ensure transactional consistency where required
3. Add DynamoDB Streams for async processing
4. Implement materialized aggregations

### 6.5 Phase 4: Data Migration

1. Create migration scripts for historical data
2. Run migrations in batches (to avoid hot partitions)
3. Validate data integrity
4. Sync any delta during migration window

### 6.6 Phase 5: Cutover

1. Switch feature flag to DynamoDB-only
2. Monitor for issues
3. Keep PostgreSQL in read-only mode for rollback
4. Decommission PostgreSQL after stabilization period

---

## 7. Files Requiring Modification

### 7.1 High Priority (Core Data Access)

| File | Changes Required |
|------|------------------|
| `src/cerebro/core/database.py` | Replace with DynamoDB client |
| `src/cerebro/core/models.py` | Convert to Pydantic + serialization |
| `src/cerebro/core/repositories.py` | Rewrite for DynamoDB |
| `src/cerebro/agents/models.py` | Convert to Pydantic + serialization |
| `src/cerebro/agents/repositories/*.py` | Rewrite for DynamoDB |
| `infra/aws/database.py` | Replace RDS with DynamoDB |

### 7.2 Medium Priority (Query Rewrites)

~130 files with SQLAlchemy queries need updating:
- `src/cerebro/api/routers/*.py` (18 files)
- `src/cerebro/analytics/*.py` (12 files)
- `src/cerebro/agents/tools/*.py` (15 files)
- `src/cerebro/findings/*.py` (6 files)
- `src/cerebro/tasks/*.py` (9 files)

### 7.3 Low Priority (Cleanup)

| Item | Action |
|------|--------|
| `migrations/` directory | Remove (no more Alembic) |
| `alembic.ini` | Remove |
| `pyproject.toml` | Remove sqlalchemy, asyncpg, alembic deps |
| `infra/gcp/database.py` | Remove or replace with Firestore |

---

## 8. Testing Strategy

### 8.1 Local Development

Use DynamoDB Local for development:

```yaml
# docker-compose.yml addition
dynamodb-local:
  image: amazon/dynamodb-local:latest
  ports:
    - "8000:8000"
  command: "-jar DynamoDBLocal.jar -sharedDb -inMemory"
```

### 8.2 Integration Tests

1. Create DynamoDB test fixtures
2. Use `moto` library for mocking in unit tests
3. Integration tests against DynamoDB Local
4. Add data validation tests comparing Postgres → DynamoDB

### 8.3 Performance Testing

1. Benchmark common query patterns
2. Test hot partition scenarios
3. Validate GSI query performance
4. Load test with production-scale data

---

## 9. Security Considerations

### 9.1 Data Classification

| Classification | Tables | Sensitivity | Encryption Requirement |
|---------------|--------|-------------|----------------------|
| **Highly Sensitive** | serval_integrations, slack_webhooks, email_configs, webhook_configs | Contains API keys, secrets, credentials | Application-level envelope encryption + DynamoDB encryption |
| **Sensitive PII** | principals, users, audit_events | Email addresses, names, IP addresses | DynamoDB encryption at rest |
| **Sensitive Security** | findings, iam_edges, config_snapshots | Security posture data | DynamoDB encryption at rest |
| **Internal** | All other tables | Business data | DynamoDB encryption at rest |

### 9.2 Encryption Architecture (DynamoDB)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ENCRYPTION LAYERS                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Layer 1: DynamoDB Server-Side Encryption (SSE)                         │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  • AWS-managed keys (default) OR Customer-managed KMS keys (CMK)   │ │
│  │  • Encrypts all data at rest automatically                         │ │
│  │  • Transparent to application                                       │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  Layer 2: Application-Level Envelope Encryption (Secrets Only)          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  • Used for: webhook URLs, SMTP passwords, API keys, OAuth tokens  │ │
│  │  • Algorithm: AES-256-GCM                                           │ │
│  │  • DEK wrapped by AWS KMS CMK                                       │ │
│  │  • Stored as Binary (B) type in DynamoDB                           │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  Layer 3: TLS in Transit                                                │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │  • All DynamoDB API calls over HTTPS (TLS 1.2+)                    │ │
│  │  • VPC Endpoints for private connectivity                          │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.3 Access Control Model

```python
# IAM Policy for DynamoDB Access (Principle of Least Privilege)

# Application Service Role
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DynamoDBTableAccess",
            "Effect": "Allow",
            "Action": [
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:BatchGetItem",
                "dynamodb:BatchWriteItem",
                "dynamodb:TransactGetItems",
                "dynamodb:TransactWriteItems"
            ],
            "Resource": [
                "arn:aws:dynamodb:*:*:table/cerebro-core-*",
                "arn:aws:dynamodb:*:*:table/cerebro-core-*/index/*",
                "arn:aws:dynamodb:*:*:table/cerebro-audit-*",
                "arn:aws:dynamodb:*:*:table/cerebro-audit-*/index/*",
                "arn:aws:dynamodb:*:*:table/cerebro-agents-*",
                "arn:aws:dynamodb:*:*:table/cerebro-agents-*/index/*",
                "arn:aws:dynamodb:*:*:table/cerebro-notifications-*",
                "arn:aws:dynamodb:*:*:table/cerebro-notifications-*/index/*"
            ],
            "Condition": {
                "ForAllValues:StringEquals": {
                    "dynamodb:LeadingKeys": ["${aws:PrincipalTag/OrgId}"]
                }
            }
        },
        {
            "Sid": "KMSDecrypt",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": "arn:aws:kms:*:*:key/cerebro-dek-key"
        }
    ]
}
```

### 9.4 Multi-Tenancy Isolation

**Current (PostgreSQL)**: Row-level security via `org_id` foreign key and application-level filtering.

**DynamoDB Approach**:
1. **Partition Key Isolation**: All tenant data partitioned by `ORG#<org_id>` prefix
2. **IAM Condition Keys**: Use `dynamodb:LeadingKeys` condition for API-level enforcement
3. **Application Validation**: Verify org_id in all repository methods
4. **Audit Logging**: CloudTrail for all DynamoDB API calls

```python
# Multi-tenant repository pattern
class TenantAwareRepository:
    def __init__(self, dynamodb: DynamoDBClient, org_id: UUID):
        self.table = dynamodb.core_table
        self.org_id = org_id
        self._org_prefix = f"ORG#{org_id}"
    
    async def get_finding(self, finding_id: UUID) -> Optional[Finding]:
        response = self.table.get_item(
            Key={
                "PK": self._org_prefix,  # Tenant isolation
                "SK": f"FIND#{finding_id}",
            }
        )
        item = response.get("Item")
        if item and item.get("org_id") == str(self.org_id):  # Double-check
            return Finding.from_dynamodb(item)
        return None
```

### 9.5 Audit Trail Requirements

| Requirement | PostgreSQL (Current) | DynamoDB (Proposed) |
|-------------|---------------------|---------------------|
| Data access logging | Application logs | CloudTrail + Application logs |
| Schema changes | Alembic migration history | N/A (schemaless) |
| Data modifications | `updated_at` columns | DynamoDB Streams + audit table |
| Admin actions | Application audit table | CloudTrail + IAM Access Analyzer |
| Compliance evidence | SQL query exports | DynamoDB Export to S3 + Athena |

### 9.6 Data Retention & Deletion

```python
# TTL-based automatic deletion for audit_events
{
    "PK": "ACCT#abc123",
    "SK": "EVENT#2024-12-10T10:30:00Z#event-id",
    "expires_at": 1734278400,  # Unix timestamp (90 days from creation)
    # ... other attributes
}

# For GDPR right-to-deletion (principals with PII)
async def delete_principal_data(org_id: UUID, principal_id: UUID):
    """Delete all data associated with a principal (GDPR compliance)."""
    # 1. Delete principal record
    # 2. Delete associated IAM edges (via Streams + Lambda)
    # 3. Anonymize findings (remove principal_id reference)
    # 4. Delete identity cluster memberships
    # 5. Audit log the deletion
```

---

## 10. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation | Owner |
|------|------------|--------|------------|-------|
| **Hot partitions** on high-write tables (audit_events) | Medium | High | Write sharding with random suffix; use account_id partitioning | Platform |
| **GSI eventual consistency** causes stale reads | Medium | Medium | Use strongly consistent reads for critical paths; document eventual consistency behavior | Platform |
| **25-item transaction limit** causes data inconsistency | Medium | High | Redesign transaction boundaries; use DynamoDB Streams for eventual consistency | Platform |
| **Complex query migration** causes feature regression | High | High | Comprehensive integration tests; parallel read validation; phased rollout | Engineering |
| **GCP support loss** impacts multi-cloud customers | Low | High | Evaluate Firestore abstraction or ScyllaDB Alternator; document as breaking change | Product |
| **Cost increase** exceeds budget | Medium | Medium | Implement read caching (ElastiCache); monitor with Cost Explorer; set billing alerts | SRE |
| **Data migration corruption** | Low | Critical | Checksums on all migrated records; parallel validation queries; rollback procedure | Platform |
| **Performance regression** on complex queries | Medium | High | Pre-compute aggregations; add OpenSearch for full-text; benchmark all query patterns | Platform |
| **Operational knowledge gap** | Medium | Medium | Training sessions; runbook documentation; shadowing with AWS support | SRE |
| **Encryption key rotation** complexity | Low | Medium | Use AWS-managed rotation; test rotation procedure in staging | Security |

### 10.1 Rollback Strategy

```
Phase 1-2 (Dual-Read):
  Rollback: Disable feature flag, revert to PostgreSQL-only reads
  Time: < 5 minutes
  Data Loss: None

Phase 3 (Dual-Write):
  Rollback: Disable DynamoDB writes, continue PostgreSQL-only
  Time: < 5 minutes
  Data Loss: None (PostgreSQL remains source of truth)

Phase 4 (Data Migration):
  Rollback: Stop migration, PostgreSQL remains authoritative
  Time: < 1 hour
  Data Loss: None

Phase 5 (Cutover):
  Rollback: Re-enable PostgreSQL writes, sync delta from DynamoDB
  Time: < 4 hours
  Data Loss: Potential for conflicts requiring manual resolution
```

---

## 11. Cost Analysis

### 11.1 Current PostgreSQL Costs (Monthly)

| Component | Specification | Monthly Cost |
|-----------|--------------|--------------|
| AWS RDS (Production) | db.r6g.xlarge, Multi-AZ, 500GB | $1,200 |
| AWS RDS (Staging) | db.r6g.large, Single-AZ, 100GB | $300 |
| GCP Cloud SQL (DR) | db-custom-4-16384, HA, 200GB | $600 |
| Backup Storage | 30-day retention, ~200GB | $50 |
| **Total** | | **$2,150/month** |

### 11.2 Projected DynamoDB Costs (Monthly)

| Component | Specification | Monthly Cost |
|-----------|--------------|--------------|
| **cerebro-core** | | |
| - Storage | ~50 GB | $12.50 |
| - On-demand reads | ~100M RCU/month | $25 |
| - On-demand writes | ~20M WCU/month | $25 |
| - GSI storage (3 GSIs) | ~150 GB | $37.50 |
| **cerebro-audit** | | |
| - Storage | ~500 GB | $125 |
| - On-demand reads | ~50M RCU/month | $12.50 |
| - On-demand writes | ~200M WCU/month | $250 |
| - GSI storage (1 GSI) | ~500 GB | $125 |
| **cerebro-agents** | | |
| - Storage | ~30 GB | $7.50 |
| - On-demand reads | ~20M RCU/month | $5 |
| - On-demand writes | ~10M WCU/month | $12.50 |
| **cerebro-notifications** | | |
| - Storage | ~5 GB | $1.25 |
| - On-demand reads | ~5M RCU/month | $1.25 |
| - On-demand writes | ~2M WCU/month | $2.50 |
| **Additional Services** | | |
| - DynamoDB Streams | ~200M records/month | $5 |
| - Point-in-time Recovery | All tables | $50 |
| - Global Tables (optional) | N/A initially | $0 |
| **Total DynamoDB** | | **$697.50/month** |

### 11.3 Additional Infrastructure Costs

| Component | Purpose | Monthly Cost |
|-----------|---------|--------------|
| OpenSearch (optional) | Full-text search on config/audit | $300-500 |
| ElastiCache Redis | Read caching | $100-200 |
| Lambda (Streams processing) | Cascade deletes, aggregations | $20-50 |
| CloudWatch | Enhanced monitoring | $50 |
| **Total Additional** | | **$470-800/month** |

### 11.4 Cost Comparison Summary

| Scenario | Monthly Cost | vs. Current |
|----------|--------------|-------------|
| Current PostgreSQL | $2,150 | baseline |
| DynamoDB Only | $700 | -67% |
| DynamoDB + OpenSearch + Cache | $1,300 | -40% |
| DynamoDB + All Options | $1,500 | -30% |

**Note**: Costs assume on-demand capacity. Provisioned capacity with reserved capacity could reduce costs by additional 20-30% once usage patterns stabilize.

---

## 12. Success Criteria

### 12.1 Functional Requirements

- [ ] All 47 existing API endpoints function correctly
- [ ] All 130+ query patterns produce identical results
- [ ] Multi-tenant isolation verified (cross-org data access prevented)
- [ ] All CRUD operations work for all 47 entity types
- [ ] Pagination works correctly with DynamoDB cursors
- [ ] Sorting works for all sortable fields
- [ ] Filtering works for all filterable fields

### 12.2 Performance Requirements

- [ ] Query latency P50 < 10ms for single-item lookups
- [ ] Query latency P99 < 100ms for list operations
- [ ] Query latency P99 < 500ms for complex aggregations
- [ ] Write latency P99 < 50ms for single-item writes
- [ ] Batch operations complete within 5x single operation time
- [ ] No query timeouts under normal load

### 12.3 Data Integrity Requirements

- [ ] Zero data loss during migration (100% record count match)
- [ ] All field values match between PostgreSQL and DynamoDB
- [ ] All relationships preserved (verified via reference integrity checks)
- [ ] Encrypted fields successfully decrypt in DynamoDB
- [ ] SHA-256 checksums match for all migrated records

### 12.4 Operational Requirements

- [ ] All tests passing (unit, integration, e2e)
- [ ] Monitoring dashboards operational
- [ ] Alerting configured for DynamoDB metrics
- [ ] Runbooks documented and validated
- [ ] On-call team trained on DynamoDB operations
- [ ] Backup and restore procedures tested

### 12.5 Cost Requirements

- [ ] Monthly cost within 50% of PostgreSQL baseline (Phase 1)
- [ ] Monthly cost within 30% of PostgreSQL baseline (steady state)
- [ ] No unexpected cost spikes from GSI usage
- [ ] Cost allocation tags configured for chargeback

---

## 13. Open Questions

### 13.1 Architecture Decisions Required

| Question | Options | Recommendation | Decision Owner |
|----------|---------|----------------|----------------|
| **GCP Support** | A) Drop GCP support B) Add Firestore C) Use ScyllaDB Alternator | B) Firestore with abstraction layer | Product/Engineering |
| **Data Retention** | A) Keep forever B) 90-day TTL C) 1-year TTL D) Tiered | C) 1-year for audit, 90-day for telemetry | Compliance/Product |
| **Search Strategy** | A) Denormalize B) OpenSearch C) Athena | B) OpenSearch for config/audit | Engineering |
| **Aggregation Model** | A) Real-time compute B) Pre-computed C) Hybrid | C) Hybrid with Streams | Engineering |
| **Consistency Model** | A) Strong everywhere B) Eventual everywhere C) Mixed | C) Strong for writes, eventual for reads | Engineering |

### 13.2 Technical Questions

1. **Transaction Scope**: Which multi-entity operations require ACID transactions?
   - Finding + EvidenceArtifact creation?
   - User + RefreshToken creation?
   - AgentSession + AgentMessage creation?

2. **Hot Partition Prevention**: How do we handle accounts with >10M audit events?
   - Time-based partitioning?
   - Random suffix sharding?
   - Separate tables per large tenant?

3. **Query Migration**: How do we handle these PostgreSQL-specific patterns?
   - `SELECT DISTINCT` queries
   - `GROUP BY` with `HAVING` clauses
   - Subqueries in WHERE clauses
   - Self-joins (e.g., identity clustering)

4. **Backup Strategy**: What RPO/RTO requirements?
   - Point-in-time recovery sufficient?
   - Cross-region backup needed?
   - How to handle backup testing?

### 13.3 Organizational Questions

5. **Team Readiness**: What training is needed?
   - DynamoDB data modeling workshop
   - NoSQL query pattern training
   - Operational runbook review

6. **Rollout Strategy**: Which customers go first?
   - Internal dogfooding first?
   - Small customers first?
   - Opt-in beta program?

7. **Documentation Updates**: What needs updating?
   - API documentation (pagination changes)
   - SDK documentation
   - Integration guides

---

## Appendices

## Appendix A: Entity Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CEREBRO DATA MODEL                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐
│ Organization │
│   (org_id)   │
└──────┬───────┘
       │ 1:N
       ├────────────────┬─────────────────┬──────────────────┐
       ▼                ▼                 ▼                  ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐  ┌──────────────┐
│   Account    │ │    Policy    │ │   Finding    │  │ AgentSession │
│ (account_id) │ │ (policy_id)  │ │ (finding_id) │  │ (session_id) │
└──────┬───────┘ └──────┬───────┘ └──────────────┘  └──────┬───────┘
       │ 1:N            │ 1:N                              │ 1:N
       ├────────┐       ▼                                  ▼
       ▼        ▼  ┌──────────────┐                 ┌──────────────┐
┌──────────┐ ┌─────────┐│    Rule      │                 │ AgentMessage │
│Principal │ │Resource ││  (rule_id)   │                 │ (message_id) │
│(princ_id)│ │(res_id) │└──────────────┘                 └──────────────┘
└────┬─────┘ └────┬────┘
     │            │
     └─────┬──────┘
           │ N:M
           ▼
    ┌──────────────┐
    │   IAMEdge    │
    │  (edge_id)   │
    └──────────────┘
```

---

## Appendix B: DynamoDB Key Design Reference

### Partition Key Design Principles

1. **High cardinality**: Use org_id, account_id, or session_id
2. **Even distribution**: Avoid time-based partitions that create hot spots
3. **Query isolation**: Partition by most common query dimension

### Sort Key Design Principles

1. **Hierarchical**: Use prefixes like `ACCT#`, `PRIN#`, `FIND#`
2. **Range queries**: Include timestamp for time-based access
3. **Uniqueness**: Append entity ID to ensure uniqueness

### GSI Design Principles

1. **Sparse indexes**: Only index items that need the access pattern
2. **Projection**: Use KEYS_ONLY or specific attributes to reduce cost
3. **Write amplification**: Each GSI adds write cost
