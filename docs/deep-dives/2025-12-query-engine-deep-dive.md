# Query Engine Deep Dive (2025-12)

The Cerebro “query engine” is a **Steampipe-inspired** runtime SQL interface that queries provider APIs in real time.

It is **not** the Snowflake warehouse. The query engine exists to support:

- investigative workflows (“show me suspicious IAM bindings”) without requiring pre-ingestion
- interactive exploration across heterogeneous providers
- agent/tool workflows that want a SQL-ish interface

---

## 1) Core module map

### Parser + engine

- `src/cerebro/query/engine.py`
  - `SQLParser`: converts a SQL-ish string into a `QueryPlan`
  - `QueryEngine`: executes a plan by invoking provider tables

### Registry + bootstrapping

- `src/cerebro/query/registry.py`: `TableRegistry`, `security_table` decorator
- `src/cerebro/query/bootstrap.py`:
  - `ensure_tables_registered()`
  - `get_query_engine()` (shared singleton by default)

### Table abstraction

- `src/cerebro/query/table.py`:
  - `SecurityTable`: provider table interface
  - `QueryContext`: org/user/provider context
  - `QueryFilter`: normalized `column operator value`

### Provider table implementations

- `src/cerebro/providers/tables/__init__.py`: `register_all_provider_tables()`
- `src/cerebro/providers/tables/*_tables.py`: concrete tables per provider

---

## 2) Boot + lifecycle

### Global registry and “register once” behavior

`src/cerebro/query/bootstrap.py:ensure_tables_registered()`:

- uses a module-level `_tables_registered` flag
- only bootstraps the global registry (`get_registry()`)
- custom registries (used in tests) are assumed to be managed by the caller

Implications:

- In a multi-worker API deployment, each worker process will register tables once.
- Import-time failures are handled defensively in `providers/tables/__init__.py` so one broken provider module doesn’t break all query capabilities.

### Shared engine instance

`get_query_engine(shared=True)` caches a singleton engine as an attribute on the function object.

Pros:

- avoids re-registration overhead
- centralizes registry state

Cons:

- subtle test isolation issues if tests forget `reset_query_engine_cache()`

---

## 3) SQL parsing model (what is supported)

### 3.1 Supported grammar (practical)

The parser (`SQLParser`) is intentionally simple. It supports:

- `SELECT <cols> FROM <table>`
- optional `WHERE <conditions>`
- optional `ORDER BY` / `LIMIT` / `OFFSET`

It uses `sqlparse` as a tokenizer but performs its own extraction.

Code anchor: `src/cerebro/query/engine.py:SQLParser.parse_query()`.

### 3.2 Wildcard table expansion

If `FROM` contains `*`, the registry expands it:

- `registry.find_tables_by_pattern(table_name)`
- the `QueryPlan` stores `wildcard_tables` to indicate fan-out execution

This supports patterns like:

```sql
SELECT * FROM aws_* WHERE account_id = '...'
```

But fan-out has a cost: the engine executes each table query and then unions the results.

### 3.3 WHERE filters (important limitations)

`SQLParser._parse_filter_conditions()`:

- splits on literal ` AND `
- recognizes operators in a fixed list: `>=`, `<=`, `!=`, `=`, `>`, `<`, `ILIKE`, `LIKE`, `IN`

Notably **does not** support:

- parentheses / precedence
- `OR` (workarounds exist; see below)
- `NOT`, `IS NULL`, `BETWEEN`, etc.

This is why a lot of higher-level queries have been refactored to avoid `OR` in the raw query-engine SQL strings.

### 3.4 Filter normalization + wildcard semantics

Recent hardening (code-level behavior):

- `_normalize_filter_column()` strips:
  - casts like `col::text`
  - qualifiers like `t.col`
  - wrappers like `LOWER(col)`
- wildcard matching for `LIKE` now supports:
  - prefix (`abc%`)
  - suffix (`%abc`)
  - contains (`%abc%`)

This normalization is critical because the query engine is often called from “generated SQL” contexts (agents / templates) that may include wrappers.

### 3.5 Relative timestamp parsing

`_parse_filter_value()` supports “relative time” strings like:

```sql
WHERE created_at >= NOW() - INTERVAL '24 hours'
```

It converts them to Python `datetime` objects (UTC) so providers can apply the filter natively.

---

## 4) Execution model

### 4.1 QueryPlan → Table execution

`QueryEngine.execute()` roughly:

1. Ensures provider tables are registered
2. Resolves the table by name from the registry
3. Builds a `QueryContext` (org/user/provider)
4. Invokes table methods to fetch results
5. Applies filters/order/limit/offset in-process if needed

Because providers differ:

- Some filters can be pushed down to the provider API.
- Others are applied after retrieval.

This makes correctness straightforward but creates a performance ceiling for high-cardinality queries.

### 4.2 Fan-out execution for wildcard tables

When `wildcard_tables` is present:

- execute each matching table
- merge rows
- de-duplicate (implementation dependent)

Operational hazard:

- wildcard queries can amplify API calls across providers; they should be rate-limited and monitored.

---

## 5) Practical patterns (how to write queries that work)

### 5.1 Avoid `OR`

Since the parser doesn’t support `OR`, implement it at the caller layer by splitting into multiple queries and unioning results.

Pattern:

1. Run query A (condition 1)
2. Run query B (condition 2)
3. Merge rows by a stable key (e.g. ARN / resource_id)

This pattern has already been applied in some compliance and discovery workflows.

### 5.2 Use normalized columns

Prefer `col LIKE '%x%'` instead of `LOWER(col) LIKE LOWER('%x%')`.

The engine normalizes wrappers, but writing simpler SQL reduces surprises.

### 5.3 Prefer equality over LIKE where possible

For provider APIs:

- equality filters are easier to push down
- LIKE filters usually require in-memory scanning

---

## 6) Security considerations

Because this engine can trigger live provider calls:

- Every query must be org-scoped and authorized.
- Query audit events should be emitted for investigations (see `src/cerebro/core/events.py:emit_event`).
- Rate limiting should be applied at the API boundary.

---

## 7) Recommended next hardening steps

These are “research-backed” suggestions but not yet implemented here.

1. **Formal grammar**: adopt a dedicated parser (or constrain SQL more explicitly) to support:
   - parentheses
   - OR
   - `IS NULL` / `NOT` / `BETWEEN`
2. **Typed schema for tables**: expose column metadata (type, nullable) so:
   - filter parsing can be type-aware
   - validation errors can be friendlier
3. **Pushdown optimization**: allow each `SecurityTable` to report which filters it can push down.
4. **Execution quotas**: impose a cap on wildcard fan-out (e.g. max 10 tables) and/or a cost estimate.
