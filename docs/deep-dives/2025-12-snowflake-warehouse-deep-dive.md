# Snowflake Warehouse Deep Dive (2025-12)

This document is intentionally long and detailed. It captures:

- how Cerebro currently uses Snowflake
- the exact code paths involved (session creation → query execution → schema bootstrapping → maintenance)
- Snowflake-specific design guidance with citations
- a “next steps” roadmap for a large org (governance, cost controls, security hardening)

---

## 1) What Cerebro means by “warehouse”

In Cerebro:

- The **core DB** (`DATABASE_URL`) is the system of record.
- The **warehouse** (`SNOWFLAKE_DATABASE_URL`) is an optional analytics backend for heavier queries.

### How routing works

`src/cerebro/core/analytics_db.py:get_analytics_db()`:

- if `SNOWFLAKE_DATABASE_URL` is unset → analytics routes to core async DB session
- else → analytics routes to a Snowflake-backed async wrapper session (`warehouse_async_session`)

This is a pragmatic “hybrid execution” model: same endpoint code can operate on either DB, so the SQL needs to be portable.

---

## 2) Current implementation in code

### 2.1 Connection + session

**Sync engine (Snowflake driver reality):** `src/cerebro/core/warehouse.py`

Key characteristics:

- Uses SQLAlchemy Snowflake dialect (sync).
- Defaults to `NullPool` (no persistent pool). Optionally `QueuePool` when `SNOWFLAKE_POOL_TYPE=queue`.
- `pool_pre_ping=True`.

#### Session-level observability + guardrails

Implemented via `connect_args`:

- `application`: `SNOWFLAKE_APPLICATION` (default `cerebro`)
- `session_parameters.QUERY_TAG`: `SNOWFLAKE_QUERY_TAG` or computed default `cerebro[:<component>]`
- `session_parameters.TIMEZONE`: `SNOWFLAKE_TIMEZONE` (default `UTC`)
- `session_parameters.STATEMENT_TIMEOUT_IN_SECONDS`: optional `SNOWFLAKE_STATEMENT_TIMEOUT_SECONDS`

Additionally, optional connection overrides:

- `role`: `SNOWFLAKE_ROLE`
- `warehouse`: `SNOWFLAKE_WAREHOUSE`

Why this matters:

- Query tags are the foundation for cost attribution and performance monitoring.
- Statement timeouts are one of the most effective “blast-radius reducers” for runaway analytics.
- Role/warehouse split enables separating interactive/API workloads from batch maintenance.

**Async wrapper:** `src/cerebro/core/warehouse_async.py`

- Wraps a sync SQLAlchemy session in `anyio.to_thread.run_sync` calls.
- Exposes `dialect_name` for downstream SQL dialect switching.

Operational implication: long-running warehouse queries occupy worker threads; be conservative with timeouts and pooling.

---

### 2.2 Dialect portability layer

`src/cerebro/analytics/sql_dialect.py` centralizes Snowflake vs Postgres vs SQLite differences.

Patterns present:

- time math (`DATEADD` vs `INTERVAL` vs `datetime('now', ...)`)
- case-insensitive matching (`ILIKE` vs `LOWER(x) LIKE LOWER(y)`)
- array expansion (`LATERAL FLATTEN` vs `UNNEST` vs `json_each`)
- JSON extraction (`col:"k"::string` vs `->>` vs `json_extract`)

Why this layer exists: once the codebase mixes “warehouse SQL” and “core DB SQL”, the easiest failure mode is accidental Postgres-isms creeping into endpoints.

---

### 2.3 Schema bootstrapping

`scripts/bootstrap_snowflake_warehouse.py`

Design choices:

- idempotent DDL (`CREATE TABLE IF NOT EXISTS ...`)
- no Alembic for warehouse schema (intentionally decoupled)
- optional “best practice” flags (`--best`) for constraints / clustering / derived table refresh

Notable types:

- Semi-structured / JSON: `VARIANT` columns (e.g. `findings.evidence`, `config_snapshots.normalized_config`)
- Array columns: `ARRAY` (e.g. `rules.cis`, `rules.nist_800_53`, `rules.provider`)

### 2.4 Derived table maintenance: `rule_controls`

Why it exists:

- Compliance endpoints need rule→control mappings.
- Doing `FLATTEN(r.cis)` at request time is expensive and hard to optimize.

So we maintain `rule_controls(rule_id, framework, control_id)`.

Maintenance paths:

- Script path: `scripts/bootstrap_snowflake_warehouse.py::_refresh_rule_controls()`
- Runtime path (Celery): `src/cerebro/tasks/warehouse_tasks.py:refresh_rule_controls`

Implementation approach:

1. Create/ensure `rule_controls` exists.
2. Rebuild into a staging table.
3. Atomically `SWAP WITH`.
4. Drop staging.

Critically, staging creation uses:

```sql
CREATE OR REPLACE TABLE rule_controls_staging LIKE rule_controls COPY GRANTS
```

This preserves reader permissions across swaps.

---

## 3) Snowflake research: guidance we should align with

Below are Snowflake concepts directly relevant to Cerebro’s usage patterns.

### 3.1 `COPY GRANTS`, `SWAP WITH`, and atomic refreshes

- `CREATE TABLE ... LIKE` supports `COPY GRANTS`.
- `ALTER TABLE ... SWAP WITH ...` swaps two tables atomically.

Implication for Cerebro:

- If we rely on atomic `SWAP`, we must preserve grants on the *incoming* table. Using `COPY GRANTS` at staging creation is the simplest safe pattern.

Sources:

- CREATE TABLE (LIKE + COPY GRANTS): https://docs.snowflake.com/en/sql-reference/sql/create-table
- ALTER TABLE (SWAP WITH): https://docs.snowflake.com/en/sql-reference/sql/alter-table

### 3.2 Constraints and join elimination (`RELY`)

Snowflake can remove redundant joins when constraints are declared with `RELY` (even though they are not enforced on standard tables).

How Cerebro uses this:

- The bootstrap script can add `RELY NOT ENFORCED` PK/FK constraints to enable join elimination on common star-schema-ish joins (e.g. findings → accounts/orgs/rules).

Risk tradeoff:

- If the data violates the constraint, results can be incorrect when the optimizer trusts it.
- Therefore, treat RELY constraints as *contracts*; enforce at ingestion time or via periodic data quality checks.

Source:

- Join elimination docs: https://docs.snowflake.com/en/user-guide/join-elimination

### 3.3 Clustering keys (and when to avoid them)

Snowflake’s official guidance: clustering keys are not for every table; they are most useful for very large tables where pruning is degraded.

How this maps to Cerebro:

- Candidate high-growth tables: `findings`, `iam_edges`, event-like telemetry tables.
- Candidate clustering expressions should match the most common predicates:
  - org_id + time
  - account_id/provider
  - finding status + severity

But:

- clustering has ongoing maintenance costs.
- if tables are not large enough, it’s wasted spend.

Sources:

- Clustering keys: https://docs.snowflake.com/en/user-guide/tables-clustering-keys
- Automatic clustering / reclustering: https://docs.snowflake.com/en/user-guide/tables-auto-reclustering

### 3.4 Search Optimization Service (SOS)

SOS builds search access paths for point-lookups / selective filters and can massively reduce scanned micro-partitions.

How this maps to Cerebro:

- good fit for “interactive dashboard” queries that:
  - select a small subset of a large table
  - filter on equality / selective patterns
  - are latency-sensitive

But:

- SOS incurs ongoing costs (storage + maintenance).
- best practice is to enable it selectively and monitor.

Source:

- Cost estimation & management: https://docs.snowflake.com/en/user-guide/search-optimization/cost-estimation

### 3.5 Dynamic tables vs streams/tasks vs materialized views

Snowflake provides dynamic tables as a declarative alternative to streams/tasks.

Relevance to Cerebro:

- `rule_controls` is currently refreshed hourly by Celery.
- A Snowflake-native alternative is a dynamic table or materialized view (depending on constraints of the transformation) which shifts refresh responsibility into Snowflake.

Tradeoffs:

- Moving derived-table refresh into Snowflake reduces app operational burden.
- But it introduces:
  - Snowflake compute spend
  - operational ownership shifting to data platform
  - need for warehouse/task governance

Source:

- Dynamic tables comparison: https://docs.snowflake.com/en/user-guide/dynamic-tables-comparison

### 3.6 Query Acceleration Service (QAS)

QAS can offload parts of qualifying queries to serverless compute.

Relevance:

- Could help “spiky” dashboard queries when concurrency is unpredictable.
- Must be controlled with caps; it can increase credit usage.

Source:

- QAS: https://docs.snowflake.com/en/user-guide/query-acceleration-service

### 3.7 Caching (result cache + warehouse cache)

Practical implications for Cerebro dashboards:

- If dashboards run identical SQL repeatedly, result cache can make them effectively free.
- Minor text differences (whitespace, order, volatile functions) can defeat cache.

Source:

- Warehouse considerations (includes cache and sizing discussion): https://docs.snowflake.com/en/user-guide/warehouses-considerations

### 3.8 Account governance: access history, query history, and usage attribution

This is where “multi-billion dollar / 1000 employee” reality shows up.

Recommended baseline:

- Query tag everything (`QUERY_TAG`)
- Use ACCOUNT_USAGE views to:
  - attribute cost by workload
  - identify frequent predicates/joins for clustering/SOS decisions

Useful views:

- `SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY` for object/column usage
- `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY` for performance/cost analysis
- `SNOWFLAKE.ACCOUNT_USAGE.COLUMN_QUERY_PRUNING_HISTORY` for pruning effectiveness

Sources:

- Access history view: https://docs.snowflake.com/en/sql-reference/account-usage/access_history
- Column query pruning history: https://docs.snowflake.com/en/sql-reference/account-usage/column_query_pruning_history

### 3.9 Security posture: network policies

If Cerebro is a core security platform, the warehouse becomes sensitive.

Snowflake network policies can restrict inbound access by IP ranges and private endpoints.

Source:

- Network policies: https://docs.snowflake.com/en/user-guide/network-policies

---

## 4) What we should do next (opinionated roadmap)

This section is intentionally “executive + engineering” level.

### 4.1 Cost controls (do immediately)

1. Ensure `QUERY_TAG` always includes component + environment (API vs Celery vs local).
2. Set conservative default `STATEMENT_TIMEOUT_IN_SECONDS` for API workloads; allow higher timeouts only for batch jobs.
3. Separate warehouses:
   - interactive dashboards
   - batch refresh / backfills
4. Add a Snowflake **resource monitor** + alerting (outside Cerebro code, but mandatory operationally).

### 4.2 Performance tuning (do after cost visibility)

1. Use `ACCESS_HISTORY` / pruning history to find:
   - most common predicates
   - expensive joins
2. Add clustering keys only for tables that are both large and predicate-heavy.
3. Consider SOS on the top 1–3 lookup-heavy tables only.

### 4.3 Data correctness + contracts (do as platform matures)

1. If we rely on `RELY` constraints, enforce those relationships in ingestion pipelines.
2. Build a lightweight DQ suite:
   - orphan checks (FK integrity)
   - duplicate PK checks
   - schema drift checks (expected columns/types)
3. Decide whether derived tables (like `rule_controls`) should be:
   - Celery-maintained (app-owned)
   - Snowflake dynamic tables/tasks (warehouse-owned)

### 4.4 Security hardening

1. Enforce least-privilege roles for:
   - API read-only
   - Celery maintenance DDL
   - bootstrap/migrations
2. Prefer keypair auth or SSO integrations for automation users (org policy decision).
3. Use network policies / private connectivity.

---

## 5) Notes on Cerebro-specific Snowflake modeling decisions

### 5.1 VARIANT vs relational columns

Current pattern:

- High-cardinality/variable schemas (e.g. evidence blobs) go into `VARIANT`.
- Core join keys are strongly typed relational columns.

This matches Snowflake’s recommended “hybrid” approach: keep the join spine relational, keep flexible nested blobs semi-structured.

### 5.2 Arrays and FLATTEN

We store arrays as true Snowflake `ARRAY` types (not JSON strings), which makes:

- `LATERAL FLATTEN(input => col)` the correct expansion primitive.

But since expansion is expensive, we avoid doing it in request paths when possible (hence `rule_controls`).

---

## Sources (external)

- CREATE TABLE (LIKE, COPY GRANTS): https://docs.snowflake.com/en/sql-reference/sql/create-table
- ALTER TABLE (SWAP WITH): https://docs.snowflake.com/en/sql-reference/sql/alter-table
- Join elimination (RELY constraints): https://docs.snowflake.com/en/user-guide/join-elimination
- Clustering keys: https://docs.snowflake.com/en/user-guide/tables-clustering-keys
- Automatic clustering: https://docs.snowflake.com/en/user-guide/tables-auto-reclustering
- Search optimization cost estimation: https://docs.snowflake.com/en/user-guide/search-optimization/cost-estimation
- Dynamic tables comparison: https://docs.snowflake.com/en/user-guide/dynamic-tables-comparison
- Query acceleration service: https://docs.snowflake.com/en/user-guide/query-acceleration-service
- Warehouse considerations: https://docs.snowflake.com/en/user-guide/warehouses-considerations
- Access history (ACCOUNT_USAGE): https://docs.snowflake.com/en/sql-reference/account-usage/access_history
- Column query pruning history: https://docs.snowflake.com/en/sql-reference/account-usage/column_query_pruning_history
- Network policies: https://docs.snowflake.com/en/user-guide/network-policies
- Parameters (QUERY_TAG, STATEMENT_TIMEOUT_IN_SECONDS): https://docs.snowflake.com/en/sql-reference/parameters
