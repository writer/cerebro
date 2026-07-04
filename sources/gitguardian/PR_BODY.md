## Summary

- Promotes `gitguardian` from generated runtime shape to provider-backed reference runtime coverage.
- Aligns incidents, members, and audit events with the documented GitGuardian API paths, authentication, pagination, fixtures, deploy runtimes, and source tests.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Health endpoint: `/source-runtimes/health?source_id=gitguardian`
- Freshness: `24h0m0s`
- Provider API: `GET /v1/incidents/secrets`, `GET /v1/members`, `GET /v1/audit_logs`

## Tests

- `go test ./sources/gitguardian ./internal/sourceprojection -count=1`
- `make catalog-check`
