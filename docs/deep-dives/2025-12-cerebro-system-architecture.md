# Cerebro System Architecture Deep Dive (2025-12)

This document is a deliberately detailed internal architecture walkthrough meant to be “excessive” and durable. It focuses on:

- runtime entry points (API, Celery, CLI)
- data tier split (core DB vs optional Snowflake warehouse)
- cross-cutting concerns (auth, org scoping, observability)
- the major domain subsystems and how data moves through them

It is written from reading the code in `src/cerebro/**` and existing docs under `docs/`.

---

## 0) Fast map (what runs where)

### Entry points

- **FastAPI service**: `src/cerebro/api/main.py` (global `app`)
- **Celery worker / beat**: `src/cerebro/tasks/celery_app.py` (global `celery_app`)
- **CLI**: `src/cerebro/cli/main.py` (Typer entrypoint)

### Persistence layers

| Layer | Primary use | Implementation |
|---|---|---|
| Core DB | system-of-record / app state | `src/cerebro/core/database.py` (async SQLAlchemy engine + sessions) |
| Warehouse (optional) | analytics-heavy queries | `src/cerebro/core/warehouse.py` + `warehouse_async.py` |
| DynamoDB (optional / hybrid) | some entity storage + migrations | `src/cerebro/core/dynamodb_*` |

### Primary “planes”

1. **Ingestion plane**: integrations + collectors fetch provider state and store it as append-only snapshots and derived edges.
2. **Core plane**: enforcement, authn/authz, entity CRUD, audit trail.
3. **Analytics plane**: dashboard/risk/compliance/monitoring endpoints; optionally run against Snowflake.
4. **Agent plane**: conversational security workflows with audited tool execution.

---

## 1) Configuration model (how runtime behavior changes)

**Single source of truth**: `src/cerebro/core/config.py` (Pydantic Settings).

Notable “global toggles”:

- `DATABASE_URL` (core DB)
- `REDIS_URL` (Celery broker coordination)
- `SNOWFLAKE_DATABASE_URL` (analytics warehouse routing)
- Agent runtime config: model selection, memory, telemetry, etc.

### Environment behavior

`src/cerebro/core/database.py::_build_engine()` rewrites Postgres URLs to SQLite in `test/testing` environments. It also has SQLite-specific hooks that auto-create schema on first transaction (see “SQLite schema bootstrap” below).

---

## 2) API service deep dive

### 2.1 App wiring

`src/cerebro/api/main.py`:

- Creates a FastAPI app with custom OpenAPI (`custom_openapi()` adds servers, security scheme, examples).
- Configures **observability** via `configure_service_observability(service_name="cerebro-api")`.
- Configures **rate limiting** using SlowAPI (`Limiter`, `RateLimitExceeded`).
- Configures **CORS** based on settings.
- Registers many routers (auth, orgs, findings, compliance, agents, etc.).

### 2.2 Auth & org scoping

The system relies on:

- **JWT authentication** (`cerebro.api.auth`, `cerebro.core.security.jwt`, `cerebro.core.security.key_store.JWTKeyStore`).
- **Org-level authorization** enforced across routers (see `cerebro.api.org_access` usage, and route dependencies like `require_org_access(require_scopes(...))`).

Operational note: org-scoping is easy to regress when adding new endpoints. A good “muscle memory” is:

1. Fetch org_id from path
2. Call the org access guard dependency
3. Only then fetch any org-scoped entities

### 2.3 Analytics DB routing (core vs warehouse)

`src/cerebro/core/analytics_db.py:get_analytics_db()` picks which DB object an analytics endpoint uses:

- default yields the **core async session** (`get_db`)
- if `SNOWFLAKE_DATABASE_URL` is configured, yields a **Snowflake-backed async wrapper** (`warehouse_async_session`)

This pattern shows up in analytics endpoints such as:

- `src/cerebro/api/routers/analytics/dashboard.py` (takes both `db: AsyncSession` and `analytics_db: Any`)

Design intent: keep “core existence checks” on `db` while pushing analytic-heavy reads to `analytics_db`.

### 2.4 Operational health endpoints

`src/cerebro/api/routers/analytics/monitoring.py` shows how operational queries are written to be warehouse-portable:

- it computes dialect-specific expressions via `cerebro.analytics.sql_dialect` helpers
- then interpolates those snippets into `text(f"...{expr}...")` queries

This is one of the more “Snowflake migration sensitive” areas.

---

## 3) Celery deep dive (tasks and scheduling)

### 3.1 Celery app layout

`src/cerebro/tasks/celery_app.py`:

- defines `celery_app = Celery("cerebro", ...)`
- registers task modules via `include=[...]`
- defines multiple queues + routing rules (`collection`, `findings`, `maintenance`, `analytics`, `integrations`, ...)
- defines a `beat_schedule` for periodic tasks

### 3.2 Important scheduled jobs

Examples from `beat_schedule`:

- `cleanup_old_snapshots` / `vacuum_analyze_tables`
- analytics metrics collection
- **warehouse maintenance**: `refresh-rule-controls-hourly` -> `cerebro.tasks.warehouse_tasks.refresh_rule_controls`

Warehouse maintenance being on Celery implies:

- the analytics plane can have independent SLOs (failures don’t block the API)
- but you need monitoring/alerting to detect drift or stale derived tables

---

## 4) Core database (system of record)

### 4.1 Session management

`src/cerebro/core/database.py`:

- builds an async engine and `async_session_factory`
- provides `get_db()` dependency for FastAPI

Non-SQLite engines use an explicit pool configuration (`pool_size`, `max_overflow`, `pool_recycle`).

### 4.2 SQLite schema bootstrap (tests / smoke)

When core DB is SQLite, the module installs SQLAlchemy event listeners:

- `connect`: sets `_schema_initialized` flag
- `begin`: on first transaction, runs `Base.metadata.create_all(...)` and also attempts to create agent model tables if present

This makes “in-process ASGI tests” cheap, but it is also a footgun:

- if Alembic migrations and ORM metadata diverge, tests may pass but prod might break
- schema creation happens on first transaction, so early failures can be confusing

---

## 5) Warehouse (Snowflake) plane

This is detailed in `docs/deep-dives/2025-12-snowflake-warehouse-deep-dive.md`, but at a system level:

- `src/cerebro/core/warehouse.py` creates a **sync** SQLAlchemy engine for Snowflake.
- `src/cerebro/core/warehouse_async.py` wraps that sync session so async FastAPI endpoints can `await` it using `anyio.to_thread`.
- `scripts/bootstrap_snowflake_warehouse.py` bootstraps the schema idempotently.
- `src/cerebro/tasks/warehouse_tasks.py` maintains derived tables like `rule_controls`.

---

## 6) Query engine plane (Steampipe-like)

The query engine is *not* the same as the analytics warehouse; it’s a runtime “SQL interface over provider APIs”:

- parser + planning: `src/cerebro/query/engine.py` (`SQLParser`, `QueryPlan`)
- table registry: `src/cerebro/query/registry.py` (`TableRegistry`)
- provider table interface: `src/cerebro/query/table.py` (`SecurityTable`, `QueryContext`)

This is detailed in `docs/deep-dives/2025-12-query-engine-deep-dive.md`.

---

## 7) Agents + tool execution

Agents are treated as a first-class interaction layer:

- runtime + tool calling: `src/cerebro/agents/runtime.py`
- persistence: `src/cerebro/agents/models.py` (append-only messages, tool invocations)
- tools: `src/cerebro/agents/tools/**`

Deep dive: `docs/deep-dives/2025-12-agents-and-tools-deep-dive.md`.

---

## 8) End-to-end data flows (annotated)

### 8.1 Provider ingestion to findings

Conceptual pipeline (names simplified):

1. Integration/collector pulls external state
2. Store append-only snapshots (`config_snapshots`) + entities (`accounts`, `resources`, `principals`)
3. Derive IAM edges / effective permissions (`iam_edges`)
4. Evaluate rules (CEL) -> create/update `findings`
5. Serve API + analytics

In-code anchors:

- Core models: `src/cerebro/core/models.py` (`ConfigSnapshot`, `IamEdge`, `Finding`, `AuditEvent`, ...)
- Findings tasks: `src/cerebro/tasks/finding_tasks.py`
- Rules engine: `src/cerebro/rules/**`

### 8.2 Analytics reads

Analytics endpoints follow a “dual DB” pattern:

- `db` (core): check org exists, maybe do small writes
- `analytics_db`: large joins/aggregations (core DB by default, Snowflake when configured)

Code anchor:

- `src/cerebro/core/analytics_db.py:get_analytics_db`
- Example endpoint: `src/cerebro/api/routers/analytics/dashboard.py:get_organization_dashboard`

---

## 9) Known sharp edges (things that bite in practice)

1. **Cross-DB portability**: f-string SQL + dialect-specific functions; must be centralized in `cerebro.analytics.sql_dialect`.
2. **Async/Sync boundary for Snowflake**: Snowflake driver is sync; threadpool wrapper means:
   - blocking queries can still occupy threads
   - timeouts + pool sizing matter
3. **Test vs prod drift**: SQLite bootstrap can hide migration issues.
4. **Authorization regressions**: new routers can accidentally skip org access enforcement.

---

## 10) Pointers to existing docs worth rereading

- `docs/architecture/security-graph-layering.md`
- `docs/architecture/claude-sdk-integration.md`
- `docs/runbooks/analytics-operations.md`
- `docs/user-guide/QUERY_ENGINE.md`
