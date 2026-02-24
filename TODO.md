# Integration Improvements TODO

## Status
- **Current focus:** Phase 5 (Quality & Freshness) + Scanner Improvements

## Scanner Rule Registry (2026-02-23)
- [x] Created auto-registration system for toxic combination rules (`rule_registry.go`)
- [x] Added validation tests ensuring all rules are properly configured
- [x] Implemented `ExpectedRules` list to prevent accidental rule removal
- [x] Added MITRE ATT&CK and CIS control mappings for rules
- [x] Created comprehensive test suite for rule validation (`rule_registry_test.go`)

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
- [x] Add AWS Organizations account discovery + per-account fan-out
- [x] Support multi-region scanning with region lists per service
- [x] Rate-limit/backoff strategy per provider API
- [x] Concurrency tuning (per-service defaults + caps)
- [x] Retry classification (throttle vs auth vs transient)

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

## Deep Review Gap Closure (2026-02-24)

### Baseline Snapshot (from deep review)
- [x] Record and commit a baseline snapshot in CI logs *(via `TestRepositoryPolicyInventorySnapshot`)*:
  - total JSON policy files discovered
  - executable condition/resource policy count
  - query-only policy count
  - mixed-shape policy count and duplicate policy ID count

### P0: Policy Engine Contract Integrity

#### 1) Strict policy schema + loader hardening
- [x] Define supported JSON types in `policies/` (executable policy vs metadata mapping files)
- [x] Exclude non-policy metadata files (e.g. `policies/cerebro/control-mapping.json`) from executable policy loading
- [x] Enforce required fields for executable policies at load time:
  - `id`, `name`, `severity`, `description`
  - either (`resource` + `conditions`) **or** `query` (not mixed)
- [x] Normalize and validate severity values (`critical|high|medium|low`)
- [x] Fail fast on duplicate policy IDs with explicit file path reporting
- [x] Add unit tests for all invalid-shape cases and duplicate-ID rejection

#### 2) Resolve query-only policy execution gap
- [x] Decision checkpoint: choose canonical model *(selected hybrid Option A execution + migration guardrail)*
  - Option A: support query-based policy execution in scanner/runtime
  - Option B: migrate query-only policies to executable condition/resource policies
- [ ] If Option A (query execution):
  - [x] implement bounded read-only SQL execution path for policy queries
  - [x] enforce table allowlist + timeout + row limit pushdown
  - [x] map query result rows to deterministic finding IDs (stable dedupe keys)
  - [x] add integration tests for query policy findings + dedup + suppression flow
- [ ] If Option B (migration):
  - [ ] create migration checklist for all `99` query-only policies
  - [ ] convert high-impact categories first (endpoint/compliance/pci/m365)
  - [ ] add guardrail test to block new query-only policies from being introduced

### P0: Compliance Export Contract Fix
- [x] Align API and CLI contract for compliance export:
  - either add real `cerebro compliance export`
  - or remove CLI note from API and provide direct downloadable export via API *(implemented: API now streams ZIP directly)*
- [x] Implement audit package artifact format:
  - manifest metadata
  - control status/evidence payloads
  - optional finding excerpts per control
  - zip packaging + deterministic file naming
- [x] Add export endpoint tests for successful export and missing-framework/error paths
- [x] Add one end-to-end smoke test: framework -> pre-audit -> export artifact generated

### P1: Provider Activation and Scheduled Sync Parity

#### 1) Provider registration parity
- [x] Audit implemented provider constructors vs runtime registration list
- [x] Mark providers as `production-ready`, `beta`, or `stub/incomplete`
- [x] Added provider maturity catalog and metadata (`internal/providers/catalog.go`) covering implemented + planned providers
- [x] Register production-ready providers behind explicit config gates
  - [x] Added config-gated registration for `qualys`, `gitlab`, `cloudflare`, `salesforce`, `vault`, `slack`, `rippling`, `jamf`, `intune`, `kandji`, and `cloudtrail`
- [x] Hide or gate incomplete providers from public API listing where appropriate
  - [x] `/api/v1/providers` now hides `stub/incomplete` providers by default unless `?include_incomplete=true`

#### 2) Scheduled sync parity
- [x] Implement scheduled GCP sync path (project/scoping + table filter handling)
  - [x] Added schedule scope directives (`project=`, `projects=`, `org=`) and env fallbacks for project resolution
- [x] Implement scheduled Azure sync path (subscription scoping + table filter handling)
  - [x] Added schedule scope directive (`subscription=`) and env fallback to `AZURE_SUBSCRIPTION_ID`
- [x] Define fallback behavior for non-native/custom providers in scheduler
  - [x] Schedules now execute registered provider sync via app provider registry and maturity gating
- [x] Add integration tests for scheduler execution result per provider (`success/fail/retry`)
  - [x] Added scheduler route + retry/status tests in `internal/cli/sync_schedule_test.go`

### P1: API Surface Completeness (remove placeholders)
- [x] Replace `getAttackPath` placeholder response with real lookup and 404 behavior
- [x] Audit API handlers for placeholder notes/stub returns and track each one to closure
- [x] Add endpoint contract tests for previously stubbed handlers

### P2: End-to-End Reliability Gates
- [x] Add CI scenario: `sync -> scan -> findings -> compliance pre-audit -> compliance export`
- [x] Add regression tests ensuring no duplicate policy IDs and no non-policy JSON loaded
- [x] Add metrics dashboard/checks for:
  - loaded policy count by type
  - query-only policy count (target trend to zero or fully executed)
  - provider registration count vs implemented provider count
  - compliance export success/failure rate

### Execution Order
- [x] Milestone 1 (P0): policy loader/validation + query gap decision + compliance export contract fix
- [x] Milestone 2 (P1): provider activation + scheduled sync parity + API placeholder removal
- [x] Milestone 3 (P2): end-to-end CI gate + production metrics and regression protections

## Deep Follow-up: Snowflake Schema Idempotency + Row-Key Correctness

### A. Baseline Capture (before fixes)
- [ ] Capture baseline logs for repeat sync run of `k8s_core_service_accounts,k8s_rbac_service_account_bindings`
- [ ] Record baseline `_sync_change_history` counts by `table_name, change_type` for the two K8s tables
- [ ] Record baseline row counts for `k8s_core_service_accounts` and `k8s_rbac_service_account_bindings`
- [ ] Record baseline `resource_relationships` count and max `sync_time`

### B. Schema Evolution / Ensure-Table Idempotency
- [x] Fix K8s `getTableColumns` to read lowercase query result key (`column_name`)
- [x] Fix GCP `getTableColumns` to read lowercase query result key (`column_name`)
- [x] Fix AWS/native `getTableColumns` to read lowercase query result key (`column_name`)
- [x] Fix provider storage `getProviderTableColumns` to read lowercase query result key (`column_name`)
- [x] Change K8s ensure-table alter statements to `ADD COLUMN IF NOT EXISTS`
- [x] Change GCP ensure-table alter statements to `ADD COLUMN IF NOT EXISTS`
- [x] Use `Exec` for K8s/GCP table DDL (`CREATE TABLE`, `ALTER TABLE`)
- [ ] Verify no repeated `column ... already exists` logs on consecutive sync runs

### C. Diff / Change-Detection Correctness
- [x] Fix AWS/native `getExistingHashes` row key access to lowercase (`_cq_id`, `_cq_hash`)
- [x] Fix GCP `getExistingHashes` row key access to lowercase (`_cq_id`, `_cq_hash`)
- [x] Fix Azure `getExistingHashes` row key access to lowercase (`_cq_id`, `_cq_hash`)
- [x] Fix K8s `getExistingHashes` row key access to lowercase (`_cq_id`, `_cq_hash`)
- [ ] Validate second identical sync reports near-zero churn (no spurious re-added rows)
- [ ] Validate deletions are detected when resources are removed from source

### D. Incremental Watermark Correctness
- [x] Fix latest sync watermark lookup to lowercase key (`sync_time`)
- [x] Validate incremental start-time derivation still honors lookback
- [ ] Validate incremental tables (SecurityHub/GuardDuty/Inspector2) can reuse persisted watermark

### E. Downstream Query Consumers (lowercase row-map keys)
- [x] Fix `snowflake.CountAssets` count extraction key (`count`)
- [x] Fix CDC event decoding in `snowflake/cdc.go` to lowercase keys
- [x] Fix API sync status last sync extraction key (`last_sync`)
- [x] Audit and update remaining query-row uppercase map lookups in sync/snowflake/api packages

### F. Relationship Extraction Parity
- [x] Replace uppercase row-key accesses in relationship extractors with lowercase-safe access
- [x] Verify extractor runs without missing-key regressions
- [ ] Verify `resource_relationships` receives fresh writes (recent `sync_time`)

### G. Regression Guardrails
- [x] Add helper for Snowflake row map retrieval with lowercase normalization fallback
- [x] Use helper in critical paths (sync engines + relationship extractor)
- [x] Add tests for ensure-table idempotency when columns already exist
- [x] Add tests for lowercase existing-hash row decoding
- [x] Add tests for CDC row decoding with lowercase keys
- [x] Add tests for sync-status `last_sync` parsing from lowercase query keys
- [x] Add static regression test for new uppercase query-row key usage in critical packages

### H. Validation + Live Proof
- [x] Run `make test`
- [x] Run `make lint`
- [ ] Live sync run #1 for K8s service-account tables (capture stats)
- [ ] Live sync run #2 for same tables (confirm no schema-noise, low churn)
- [ ] Query `_sync_change_history` to validate realistic change mix
- [ ] Query `resource_relationships` count + recency after extraction
