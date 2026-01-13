# CloudQuery Integration Analysis

**Date:** 2026-01-13  
**Status:** Analysis Complete - Ready for Review

---

## 1. Current Architecture Overview

### 1.1 Core Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CEREBRO DATA PIPELINE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  INGESTION                    STORAGE                    EVALUATION          │
│  ─────────                    ───────                    ──────────          │
│                                                                              │
│  ┌─────────────┐         ┌─────────────┐           ┌─────────────┐          │
│  │ CloudQuery  │────────▶│  Snowflake  │──────────▶│   Policy    │          │
│  │    CLI      │  sync   │   Tables    │  query    │   Engine    │          │
│  └─────────────┘         │             │           │   (Cedar)   │          │
│        │                 │ • aws_*     │           └──────┬──────┘          │
│        │                 │ • gcp_*     │                  │                  │
│  CloudQuery              │ • azure_*   │                  │ evaluate         │
│  Config YAML             │ • k8s_*     │                  ▼                  │
│                          └─────────────┘           ┌─────────────┐          │
│                                 │                  │   Scanner   │          │
│                                 │                  │  (parallel) │          │
│                          ┌──────┴──────┐           └──────┬──────┘          │
│                          │ snowflake.  │                  │                  │
│                          │ GetAssets() │                  │ findings         │
│                          └─────────────┘                  ▼                  │
│                                                    ┌─────────────┐          │
│                                                    │  Findings   │          │
│                                                    │   Store     │          │
│                                                    └─────────────┘          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Key Components

| Component | Location | Purpose | Status |
|-----------|----------|---------|--------|
| CloudQuery CLI | External tool | Syncs cloud data to Snowflake | ✅ Working |
| CLI Sync Command | `internal/cli/sync.go` | Wraps CloudQuery CLI | ✅ Working |
| Snowflake Client | `internal/snowflake/` | Query/store data | ✅ Working |
| Policy Engine | `internal/policy/cedar.go` | Cedar-style evaluation | ✅ Working |
| Scanner | `internal/scanner/` | Parallel policy evaluation | ✅ Working |
| Findings Store | `internal/findings/` | Store violations | ✅ Working |
| Compliance | `internal/compliance/` | Framework mappings | ⚠️ Minimal |
| Policies | `policies/**/*.json` | 280+ JSON policies | ✅ Working |

### 1.3 The CloudQuery Package (`internal/cloudquery/`)

| File | Lines | Purpose | Verdict |
|------|-------|---------|---------|
| `policy_executor.go` | 625 | SQL-based policy engine | ❌ DUPLICATE |
| `policies_pci.go` | 286 | Hardcoded PCI policies | ❌ DUPLICATE |
| `policies_soc2.go` | 279 | Hardcoded SOC2 policies | ❌ DUPLICATE |
| `asset_source.go` | 263 | Fetch assets from Snowflake | ❌ DUPLICATE |
| `tables.go` | 497 | CloudQuery AWS table schemas | ✅ USEFUL |
| `tables_gcp.go` | 302 | CloudQuery GCP table schemas | ✅ USEFUL |
| `tables_azure.go` | 325 | CloudQuery Azure table schemas | ✅ USEFUL |
| `sync.go` | 379 | Sync utilities, inventory | ⚠️ PARTIAL |
| `*_test.go` | 321 | Tests | ✅ KEEP |

---

## 2. Problem Analysis

### 2.1 Duplicated Functionality

**Problem 1: Duplicate Policy Engine**
```
internal/policy/cedar.go          ←  EXISTING: Cedar-style JSON policies
internal/cloudquery/policy_executor.go  ←  DUPLICATE: SQL-based policies
```

Both do the same thing (evaluate security policies) but with different approaches:
- Cedar engine: Loads JSON files, evaluates in-memory
- SQL executor: Hardcoded SQL, runs against Snowflake

**Problem 2: Duplicate Asset Fetching**
```
internal/snowflake/assets.go      ←  EXISTING: GetAssets(), GetAssetByID()
internal/cloudquery/asset_source.go    ←  DUPLICATE: FetchAssets(), FetchS3Buckets()
```

Both query Snowflake for assets. The existing `snowflake.GetAssets()` is already used by `app.runScheduledScan()`.

**Problem 3: Hardcoded Policies**
```
policies/aws/*.json               ←  EXISTING: 85+ AWS policies as JSON
internal/cloudquery/policies_*.go ←  DUPLICATE: Hardcoded in Go
```

The existing policy system uses JSON files that can be edited without recompiling. The cloudquery package has policies hardcoded in Go code.

### 2.2 Missing Integration

The `internal/cloudquery/` package is **not integrated** into the application:
- Not imported in `internal/app/app.go`
- Not used by any CLI commands
- Not exposed via API
- Tests exist but aren't testing integration

### 2.3 Compliance Framework Gaps

The existing `internal/compliance/frameworks.go` has:
- ✅ CIS AWS v1.4 (5 controls)
- ✅ CIS GCP v1.2 (1 control)
- ✅ CIS Azure v1.4 (1 control)
- ✅ SOC 2 (3 controls)

Missing:
- ❌ PCI-DSS
- ❌ HIPAA
- ❌ NIST 800-53
- ❌ Full CIS coverage (should have 50+ controls each)

---

## 3. What CloudQuery Actually Does

### 3.1 CloudQuery's Purpose

CloudQuery is an **ELT (Extract, Load, Transform) tool**:
1. **Extract**: Pulls data from cloud APIs (AWS, GCP, Azure)
2. **Load**: Writes to destinations (Snowflake, PostgreSQL, etc.)
3. **Transform**: Optional dbt integration for transformations

**CloudQuery does NOT**:
- Evaluate policies (that's what Cerebro does)
- Generate findings (that's what Cerebro does)
- Store compliance results (that's what Cerebro does)

### 3.2 How Cerebro Should Use CloudQuery

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  CloudQuery     │     │    Snowflake    │     │    Cerebro      │
│  (External)     │────▶│    (Storage)    │────▶│   (Analysis)    │
│                 │     │                 │     │                 │
│ • AWS plugin    │     │ • aws_s3_*      │     │ • Policy eval   │
│ • GCP plugin    │     │ • aws_iam_*     │     │ • Findings      │
│ • Azure plugin  │     │ • aws_ec2_*     │     │ • Compliance    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### 3.3 What the CloudQuery Package Should Be

The `internal/cloudquery/` package should provide:
1. **Table Schemas**: DDL for creating CloudQuery-compatible tables (✅ already has)
2. **Schema Validation**: Verify tables exist and have expected columns
3. **Inventory Queries**: Asset counts, freshness checks
4. **NOT policies**: Those belong in `internal/policy/` and `policies/`

---

## 4. Recommended Changes

### 4.1 Files to DELETE

| File | Reason |
|------|--------|
| `internal/cloudquery/policy_executor.go` | Duplicates `internal/policy/cedar.go` |
| `internal/cloudquery/policies_pci.go` | Should be JSON in `policies/` |
| `internal/cloudquery/policies_soc2.go` | Should be JSON in `policies/` |
| `internal/cloudquery/asset_source.go` | Duplicates `internal/snowflake/assets.go` |

### 4.2 Files to KEEP

| File | Reason |
|------|--------|
| `internal/cloudquery/tables.go` | Useful schema definitions |
| `internal/cloudquery/tables_gcp.go` | Useful schema definitions |
| `internal/cloudquery/tables_azure.go` | Useful schema definitions |
| `internal/cloudquery/sync.go` | Useful utilities (after cleanup) |
| `internal/cloudquery/*_test.go` | Tests (update after changes) |

### 4.3 Files to ENHANCE

| File | Changes |
|------|---------|
| `internal/compliance/frameworks.go` | Add PCI-DSS, HIPAA, full CIS |
| `policies/aws/*.json` | Tag existing with framework controls |

### 4.4 sync.go Cleanup

The `sync.go` file has some useful functions but also some that duplicate or reference deleted code:

**KEEP:**
- `SyncClient` struct
- `EnsureTables()` - creates CloudQuery table DDL
- `GetTableStats()` - useful inventory
- `ListAvailableTables()` - useful inventory
- `GetAssetInventory()` - useful dashboard data

**REMOVE:**
- `SyncFromCloudQuery()` - uses CloudQueryURL which is for hosted CloudQuery (we use CLI)
- `syncTable()`, `insertRows()` - internal to above
- `GetComplianceOverview()` - references `policy_results` table from deleted executor
- `QueryTable()` - duplicates `snowflake.Query()`

---

## 5. Implementation Plan

### Phase 1: Cleanup (Remove Duplicates)

```bash
# Delete duplicate files
rm internal/cloudquery/policy_executor.go
rm internal/cloudquery/policies_pci.go
rm internal/cloudquery/policies_soc2.go
rm internal/cloudquery/asset_source.go

# Update sync.go to remove dead code
# Update tests to remove references to deleted code
```

### Phase 2: Refactor sync.go

Keep only:
- Table management functions
- Inventory functions
- Remove hosted CloudQuery sync (we use CLI)

### Phase 3: Enhance Compliance Frameworks

Add to `internal/compliance/frameworks.go`:
- PCI-DSS v4.0 (12 requirements, ~50 controls)
- HIPAA Security Rule (~18 controls)
- Expand CIS AWS to full benchmark (~100 controls)

### Phase 4: Policy Tagging

Review existing 85 AWS policies and ensure tags include:
- CIS control IDs (e.g., `cis-aws-1.4`)
- PCI-DSS requirement IDs (e.g., `pci-dss-1.2.1`)
- HIPAA references where applicable

### Phase 5: Verify

- All tests pass
- Build succeeds
- CI green
- No regressions in functionality

---

## 6. Summary

| Aspect | Current State | Target State |
|--------|---------------|--------------|
| Policy Engine | 2 engines (Cedar + SQL) | 1 engine (Cedar) |
| Policy Storage | JSON files + Go hardcoded | JSON files only |
| Asset Queries | 2 sources | 1 source (snowflake.GetAssets) |
| Compliance Frameworks | 4 partial | 6+ complete |
| cloudquery package | 3,277 lines (mixed) | ~1,500 lines (focused) |

**Key Principle**: CloudQuery syncs data, Cerebro analyzes it. Don't duplicate what already works.
