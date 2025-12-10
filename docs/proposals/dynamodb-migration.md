# DynamoDB Migration Design Document

**Status:** Draft  
**Author:** Engineering  
**Date:** 2024-12-10

## Executive Summary

This document outlines the migration strategy from PostgreSQL to Amazon DynamoDB for the Cerebro security platform. The migration affects ~40 SQLAlchemy models, ~130 files with database queries, and infrastructure across AWS and GCP.

---

## 1. Current State Analysis

### 1.1 Database Schema Overview

The current PostgreSQL schema consists of the following entity groups:

#### Core Entities (src/cerebro/core/models.py)
| Table | Primary Key | Key Relationships | Record Volume |
|-------|-------------|-------------------|---------------|
| `orgs` | `org_id` (UUID) | Parent of all tenant data | Low (~100s) |
| `accounts` | `account_id` (UUID) | FK → orgs, parent of principals/resources | Medium (~1000s) |
| `principals` | `principal_id` (UUID) | FK → accounts | High (~100Ks) |
| `resources` | `resource_id` (UUID) | FK → accounts | High (~100Ks) |
| `config_snapshots` | `snapshot_id` (UUID) | FK → resources | Very High (~millions) |
| `iam_edges` | `edge_id` (UUID) | FK → accounts, principals, resources | Very High (~millions) |
| `findings` | `finding_id` (UUID) | FK → orgs, accounts, rules, resources, principals | High (~100Ks) |
| `rules` | `rule_id` (UUID) | FK → policies | Medium (~1000s) |
| `policies` | `policy_id` (UUID) | FK → orgs | Low (~100s) |
| `suppressions` | `suppression_id` (UUID) | FK → orgs, rules | Low (~1000s) |
| `audit_events` | `event_id` (UUID) | FK → accounts | Very High (~millions) |

#### Agent Entities (src/cerebro/agents/models.py)
| Table | Primary Key | Key Relationships |
|-------|-------------|-------------------|
| `agent_sessions` | `id` (UUID) | FK → orgs |
| `agent_messages` | `id` (UUID) | FK → agent_sessions |
| `agent_conversation_items` | `id` (UUID) | FK → agent_sessions |
| `agent_memory_entries` | `id` (UUID) | FK → orgs, agent_sessions |
| `tool_invocations` | `id` (UUID) | FK → agent_sessions |
| `tool_approvals` | `id` (UUID) | FK → orgs, tool_invocations |
| `agent_review_tasks` | `id` (UUID) | FK → orgs, agent_sessions |
| `agent_recommendations` | `id` (UUID) | FK → agent_sessions, orgs |

#### Notification Entities
| Table | Primary Key | Key Relationships |
|-------|-------------|-------------------|
| `slack_webhooks` | `webhook_id` (UUID) | FK → orgs |
| `slack_notifications` | `notification_id` (UUID) | FK → slack_webhooks, orgs |
| `email_configs` | `config_id` (UUID) | FK → orgs |
| `email_notifications` | `notification_id` (UUID) | FK → email_configs, orgs |
| `webhook_configs` | `config_id` (UUID) | FK → orgs |
| `webhook_notifications` | `notification_id` (UUID) | FK → webhook_configs, orgs |

#### Integration Entities
| Table | Primary Key | Key Relationships |
|-------|-------------|-------------------|
| `serval_integrations` | `integration_id` (UUID) | FK → orgs (1:1) |
| `integration_sync_state` | `state_id` (UUID) | Standalone |
| `integration_sync_issue_events` | `issue_id` (UUID) | Standalone |

### 1.2 Current Query Patterns

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

### 1.3 PostgreSQL-Specific Features in Use

| Feature | Usage Location | DynamoDB Alternative |
|---------|----------------|---------------------|
| `JSONB` with GIN indexes | config_snapshots, audit_events | Denormalize or use OpenSearch |
| `ARRAY` types | rules.provider, rules.cwe | Store as JSON List |
| `UUID` with `gen_random_uuid()` | All tables | Client-side UUID generation |
| Foreign Key Constraints | All relationships | Application-level enforcement |
| `CHECK` constraints | Enum validations | Application-level validation |
| Transactions | Multi-table writes | DynamoDB Transactions (25 item limit) |

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

## 9. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Hot partitions on high-write tables | Performance degradation | Use write sharding for audit_events |
| GSI eventual consistency | Stale reads | Use strongly consistent reads where critical |
| 25-item transaction limit | Data inconsistency | Design for smaller transaction scopes |
| Complex query migration | Feature regression | Extensive testing, phased rollout |
| GCP support loss | Customer impact | Firestore abstraction or cross-cloud solution |
| Cost increase | Budget overrun | Monitor usage, implement caching |

---

## 10. Success Criteria

- [ ] All existing API endpoints function correctly
- [ ] Query latency P99 < 100ms for common patterns
- [ ] Zero data loss during migration
- [ ] Successful data validation (100% match)
- [ ] All tests passing
- [ ] Cost within 20% of PostgreSQL baseline

---

## 11. Open Questions

1. **GCP Support**: Do we need to maintain GCP database support? If yes, Firestore or alternative?
2. **Data Retention**: What TTL policies for audit_events and config_snapshots?
3. **Search Requirements**: Do we need OpenSearch for JSON field queries, or can we denormalize?
4. **Aggregation Frequency**: How often are aggregate queries run? Real-time vs batch acceptable?
5. **Transaction Boundaries**: Which operations require strong consistency?

---

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
