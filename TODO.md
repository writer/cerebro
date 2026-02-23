# Integration Improvements TODO

## Status
- **Current focus:** Phase 4 (Scale & Resilience)

## Platform Gap Audit (2026-02-23)

### Security / Access Control Gaps
- [x] Close RBAC authorization gaps for unclassified API routes (fail closed for `/api/v1/*`, explicit mappings for agents/providers/scheduler/runtime/graph/etc.)
- [x] Split coarse RBAC permissions into dedicated domains (`agents:*`, `tickets:*`, `runtime:*`, `graph:*`) to reduce over-broad access grants
- [x] Add full auth+RBAC route matrix tests to ensure every route group has explicit permission expectations

### Agent Safety / Operations Gaps
- [x] Add pending-approval TTL/expiry and cleanup behavior for stalled agent tool approvals
- [x] Persist approval audit records (approver, timestamp, tool call id, decision)

### Query Safety / Cost Control Gaps
- [x] Enforce Snowflake row-limit pushdown in SQL execution path (avoid unbounded warehouse reads before API-side truncation)
- [x] Add query budget guardrails (execution timeout/warehouse cost hints per request)

## Phase 1: Baseline & Observability
- [x] Add per-table metrics (duration, rows, errors) to sync output
- [x] Emit structured sync summary (JSON) for CI/debugging
- [x] Add Prometheus counters/histograms for sync duration and row counts
- [x] Add smoke-test CLI path (single table + table existence validation)
- [x] Standardize error wrapping to include provider/table/region

## Phase 2: Coverage Audit (AWS → GCP → Azure)
- [x] Build AWS coverage matrix (service → table → primary keys → regions)
- [x] Compare against AWS service catalog; identify missing high-value resources
- [x] Add missing AWS tables (start with IAM, EC2, S3, KMS, RDS, CloudTrail)
- [x] Build GCP coverage matrix (Asset Inventory vs native APIs)
- [x] Build Azure coverage matrix (ARM + Graph)

## Phase 3: Correctness & Schema Quality
- [x] Standardize primary keys (ARN/ID) and account/region columns
- [x] Normalize timestamps and tag schemas across providers
- [x] Validate Snowflake schemas match fetch payloads
- [x] Add schema consistency tests (column presence + type checks)
- [x] Improve diff accuracy (hash inputs, deterministic field ordering)

## Phase 4: Scale & Resilience
- [ ] Add AWS Organizations account discovery + per-account fan-out
- [ ] Support multi-region scanning with region lists per service
- [ ] Rate-limit/backoff strategy per provider API
- [ ] Concurrency tuning (per-service defaults + caps)
- [ ] Retry classification (throttle vs auth vs transient)

## Phase 5: Quality & Freshness
- [ ] Incremental sync rules for large tables (delta windows)
- [ ] Better deletion semantics for regional vs global tables
- [ ] Relationship extraction parity with asset tables
- [ ] Backfill strategy for partial API responses

## Phase 6: Provider Expansion
- [ ] GCP: IAM, Compute, Storage, KMS, Org policy, SCC, Artifact Registry depth
- [ ] Azure: Graph identities, RBAC, Key Vault, Defender, Storage, AKS
- [ ] Kubernetes: cluster inventory + RBAC posture tables
- [ ] SaaS: GitHub/Okta/Snyk/Wiz sync parity

## Progress Log
- 2026-01-28: Completed Phase 1 observability and validation improvements.

## Deep Follow-up: Snowflake Schema Idempotency + Row-Key Correctness

### A. Baseline Capture (before fixes)
- [ ] Capture baseline logs for repeat sync run of `k8s_core_service_accounts,k8s_rbac_service_account_bindings`
- [ ] Record baseline `_sync_change_history` counts by `table_name, change_type` for the two K8s tables
- [ ] Record baseline row counts for `k8s_core_service_accounts` and `k8s_rbac_service_account_bindings`
- [ ] Record baseline `resource_relationships` count and max `sync_time`

### B. Schema Evolution / Ensure-Table Idempotency
- [ ] Fix K8s `getTableColumns` to read lowercase query result key (`column_name`)
- [ ] Fix GCP `getTableColumns` to read lowercase query result key (`column_name`)
- [ ] Fix AWS/native `getTableColumns` to read lowercase query result key (`column_name`)
- [ ] Fix provider storage `getProviderTableColumns` to read lowercase query result key (`column_name`)
- [ ] Change K8s ensure-table alter statements to `ADD COLUMN IF NOT EXISTS`
- [ ] Change GCP ensure-table alter statements to `ADD COLUMN IF NOT EXISTS`
- [ ] Use `Exec` for K8s/GCP table DDL (`CREATE TABLE`, `ALTER TABLE`)
- [ ] Verify no repeated `column ... already exists` logs on consecutive sync runs

### C. Diff / Change-Detection Correctness
- [ ] Fix AWS/native `getExistingHashes` row key access to lowercase (`_cq_id`, `_cq_hash`)
- [ ] Fix GCP `getExistingHashes` row key access to lowercase (`_cq_id`, `_cq_hash`)
- [ ] Fix Azure `getExistingHashes` row key access to lowercase (`_cq_id`, `_cq_hash`)
- [ ] Fix K8s `getExistingHashes` row key access to lowercase (`_cq_id`, `_cq_hash`)
- [ ] Validate second identical sync reports near-zero churn (no spurious re-added rows)
- [ ] Validate deletions are detected when resources are removed from source

### D. Incremental Watermark Correctness
- [ ] Fix latest sync watermark lookup to lowercase key (`sync_time`)
- [ ] Validate incremental start-time derivation still honors lookback
- [ ] Validate incremental tables (SecurityHub/GuardDuty/Inspector2) can reuse persisted watermark

### E. Downstream Query Consumers (lowercase row-map keys)
- [ ] Fix `snowflake.CountAssets` count extraction key (`count`)
- [ ] Fix CDC event decoding in `snowflake/cdc.go` to lowercase keys
- [ ] Fix API sync status last sync extraction key (`last_sync`)
- [ ] Audit and update remaining query-row uppercase map lookups in sync/snowflake/api packages

### F. Relationship Extraction Parity
- [ ] Replace uppercase row-key accesses in relationship extractors with lowercase-safe access
- [ ] Verify extractor runs without missing-key regressions
- [ ] Verify `resource_relationships` receives fresh writes (recent `sync_time`)

### G. Regression Guardrails
- [ ] Add helper for Snowflake row map retrieval with lowercase normalization fallback
- [ ] Use helper in critical paths (sync engines + relationship extractor)
- [ ] Add tests for ensure-table idempotency when columns already exist
- [ ] Add tests for lowercase existing-hash row decoding
- [ ] Add tests for CDC row decoding with lowercase keys
- [ ] Add tests for sync-status `last_sync` parsing from lowercase query keys
- [ ] Add static regression test for new uppercase query-row key usage in critical packages

### H. Validation + Live Proof
- [ ] Run `make test`
- [ ] Run `make lint`
- [ ] Live sync run #1 for K8s service-account tables (capture stats)
- [ ] Live sync run #2 for same tables (confirm no schema-noise, low churn)
- [ ] Query `_sync_change_history` to validate realistic change mix
- [ ] Query `resource_relationships` count + recency after extraction
