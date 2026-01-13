# CloudQuery Integration Progress

**Started:** 2026-01-13  
**Status:** COMPLETE

---

## Summary

Refactoring the `internal/cloudquery/` package to be a clean, focused utility layer for CloudQuery table management, while enhancing the existing compliance framework with proper policy mappings.

---

## Completed

### Phase 1: Cleanup ✅

Removed duplicate code that was creating a parallel policy system:
- Deleted `policy_executor.go` (625 lines) - duplicated Cedar engine
- Deleted `policies_pci.go` (286 lines) - hardcoded policies
- Deleted `policies_soc2.go` (279 lines) - hardcoded policies
- Deleted `asset_source.go` (263 lines) - duplicated snowflake.GetAssets()

**Total removed:** 1,453 lines of duplicate code

### Phase 2: Refactor cloudquery Package ✅

Rewrote `sync.go` as clean `TableManager`:
- `NewTableManager()` - create manager with Snowflake client
- `EnsureTables()` - create CloudQuery DDL in Snowflake
- `EnsureAWSTables()`, `EnsureGCPTables()`, `EnsureAzureTables()` - provider-specific
- `GetTableStats()` - row count, last sync, unique accounts
- `ListAvailableTables()` - list CloudQuery tables in schema
- `GetAssetInventory()` - asset counts by table
- `CheckDataFreshness()` - check if data is stale (>24h)

Updated tests to match new structure.

**Current cloudquery package:**
```
internal/cloudquery/
├── sync.go          # TableManager utilities (refactored)
├── sync_test.go     # Tests (updated)
├── tables.go        # AWS table schemas (kept)
├── tables_gcp.go    # GCP table schemas (kept)
├── tables_azure.go  # Azure table schemas (kept)
└── tables_test.go   # Table tests (kept)
```

---

## Current State

### Existing Policies (350 total)

| Directory | Count | Description |
|-----------|-------|-------------|
| aws | 85 | AWS security policies |
| wiz | 114 | Wiz-style attack path policies |
| azure | 31 | Azure policies |
| gcp | 29 | GCP policies |
| kubernetes | 16 | K8s policies |
| github | 16 | GitHub security policies |
| ai | 14 | AI/ML policies |
| cicd | 8 | CI/CD pipeline policies |
| dspm | 8 | Data security policies |
| runtime | 8 | Runtime detection policies |
| api | 6 | API security policies |
| okta | 5 | Identity provider policies |
| m365 | 4 | Microsoft 365 policies |
| sentinelone | 3 | EDR policies |
| cross-provider | 2 | Multi-cloud policies |
| telemetry | 1 | Telemetry policies |

### CIS Controls Already Tagged in Policies

Policies already have CIS control IDs in their tags:
- `cis-aws-1.4`, `cis-aws-1.5`, `cis-aws-1.8`, `cis-aws-1.9`, `cis-aws-1.10`
- `cis-aws-1.12`, `cis-aws-1.14`, `cis-aws-1.15`, `cis-aws-1.16`
- `cis-aws-2.1.1`, `cis-aws-2.1.2`, `cis-aws-2.1.5`, `cis-aws-2.2.1`
- `cis-aws-2.3.1`, `cis-aws-2.3.3`, `cis-aws-2.6`
- `cis-aws-3.1`, `cis-aws-3.5`, `cis-aws-3.6`, `cis-aws-3.8`, `cis-aws-3.9`
- `cis-aws-4.1`, `cis-aws-4.15`
- `cis-aws-5.2`, `cis-aws-5.3`, `cis-aws-5.4`, `cis-aws-5.6`

**27 unique CIS controls** already mapped in policy tags.

### Current Compliance Frameworks

`internal/compliance/frameworks.go` has:
- CIS AWS v1.4 (5 controls mapped)
- CIS GCP v1.2 (1 control mapped)
- CIS Azure v1.4 (1 control mapped)
- SOC 2 (3 controls mapped)

**Gap:** Framework definitions don't reflect all 27+ CIS controls already in policies.

---

## Completed

### Phase 3: Wire cloudquery into app.go ✅

- Added `CloudQuery *cloudquery.TableManager` to App struct
- Added `initCloudQuery()` initialization function
- TableManager initializes when Snowflake is available

### Phase 4: Enhance Compliance Frameworks ✅

Enhanced `internal/compliance/frameworks.go`:
- **CIS AWS v1.5**: 25 controls mapped to existing policies
- **PCI-DSS v4.0**: 16 controls covering Reqs 1-12
- **HIPAA Security Rule**: 11 controls (164.308, 164.312)
- **SOC 2 Type II**: 10 controls (CC6, CC7, CC8, A1)
- **CIS GCP v1.3**: 5 controls mapped
- **CIS Azure v1.5**: 5 controls mapped

Added utility functions:
- `GetFrameworkIDs()` - list all framework IDs
- `GetControlsForPolicy()` - find controls for a given policy

### Phase 5: Add API Endpoints ✅

Added CloudQuery endpoints:
- `GET /api/v1/cloudquery/tables` - list available tables
- `GET /api/v1/cloudquery/inventory` - asset inventory by table
- `GET /api/v1/cloudquery/freshness/{table}` - data freshness check
- `GET /api/v1/cloudquery/stats/{table}` - table statistics
- `POST /api/v1/cloudquery/ensure-tables` - create DDL (optional ?provider=aws|gcp|azure)

---

## Architecture After Changes

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           internal/app/app.go                                │
│                                                                              │
│  App struct {                                                                │
│      // Core (existing)                                                      │
│      Snowflake    *snowflake.Client      ←── Query CloudQuery tables        │
│      Policy       *policy.Engine         ←── Evaluate Cedar policies        │
│      Scanner      *scanner.Scanner       ←── Parallel evaluation            │
│      Findings     *findings.Store        ←── Store violations               │
│                                                                              │
│      // CloudQuery (new)                                                     │
│      CloudQuery   *cloudquery.TableManager  ←── Table management            │
│                                                                              │
│      // Compliance (enhanced)                                                │
│      // Uses frameworks.go with expanded controls                            │
│  }                                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Next Steps

- [x] Wire `TableManager` into `app.go`
- [x] Expand compliance frameworks
- [x] Add API endpoints
- [ ] Test end-to-end with live Snowflake
- [ ] Push to GitHub and verify CI passes
