# Codebase Improvement Plan

## 1. Technical Debt & Shortcuts

### High Priority
- **Finding Store Persistence**: The in-memory store in `internal/findings/store.go` loses data on restart. Needs a persistent backend (SQLite/PostgreSQL) for dev/test environments.
- **Policy/Table Mapping**: No validation exists between policies and required CloudQuery tables. Policies can fail silently if tables are missing.
- **Hardcoded Secrets/Values**: Several potential hardcoded values or "TODO" placeholders in codebase need review (e.g., `internal/graph/effective_permissions.go` has a TODO about adding group/role denies).

### Medium Priority
- **Rate Limiting**: `internal/api/ratelimit.go` and scan endpoints lack robust rate limiting for expensive operations.
- **Incremental Scanning**: `internal/scanner/incremental.go` has placeholders but needs full implementation to avoid re-scanning unchanged assets.
- **Error Handling**: Various `TODO` comments indicate swallowed errors or incomplete error handling paths.

## 2. Missing Features

### Compliance & Reporting
- **Scoring Logic**: Compliance score is currently a simple average. Needs weighted scoring based on control severity (mentioned in `compliance/frameworks.go`).
- **Data Freshness**: While some checks exist, more robust enforcement of data freshness before running policies is needed across all providers.

### Security Graph
- **Graph Completeness**: `internal/graph/effective_permissions.go` needs to account for SCPs and explicit denies.
- **Attack Paths**: MITRE mappings and attack path analysis need expansion (several TODOs in `internal/graph/`).

## 3. Testing & Validation
- **Integration Tests**: Lack of comprehensive integration tests for the full scan->policy->finding flow.
- **Mocking**: More extensive mocking needed for CloudQuery and Snowflake dependencies to enable better unit testing.

## Action Plan

1.  **Persistence Layer**: Implement a file-based or SQLite backend for `findings/store.go` to support restart persistence.
2.  **Validation**: Create a mapping registry for Policy -> Required Tables and validate on startup.
3.  **Graph Enhancement**: complete the effective permissions model to include deny rules and SCPs.
4.  **Refactoring**: Address high-priority TODOs in `internal/graph` and `internal/scanner`.
