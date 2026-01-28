# Integration Improvements TODO

## Status
- **Current focus:** Phase 2 (Coverage Audit)

## Phase 1: Baseline & Observability
- [x] Add per-table metrics (duration, rows, errors) to sync output
- [x] Emit structured sync summary (JSON) for CI/debugging
- [x] Add Prometheus counters/histograms for sync duration and row counts
- [x] Add smoke-test CLI path (single table + table existence validation)
- [x] Standardize error wrapping to include provider/table/region

## Phase 2: Coverage Audit (AWS → GCP → Azure)
- [ ] Build AWS coverage matrix (service → table → primary keys → regions)
- [ ] Compare against AWS service catalog; identify missing high-value resources
- [ ] Add missing AWS tables (start with IAM, EC2, S3, KMS, RDS, CloudTrail)
- [ ] Build GCP coverage matrix (Asset Inventory vs native APIs)
- [ ] Build Azure coverage matrix (ARM + Graph)

## Phase 3: Correctness & Schema Quality
- [ ] Standardize primary keys (ARN/ID) and account/region columns
- [ ] Normalize timestamps and tag schemas across providers
- [ ] Validate Snowflake schemas match fetch payloads
- [ ] Add schema consistency tests (column presence + type checks)
- [ ] Improve diff accuracy (hash inputs, deterministic field ordering)

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
