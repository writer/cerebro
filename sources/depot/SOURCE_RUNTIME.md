# Depot

Generated Source Runtime SDK scaffold for `depot`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/depot`
- Health endpoint: `/source-runtimes/health?source_id=depot`
- Source health receipt: `sources/depot/source_health_receipt.json`
- EvidenceCAS reference kind: `depot.evidence_cas_reference`

## Families

- `users`, emits `depot.users`, reads `/v1/users`
- `projects`, emits `depot.projects`, reads `/v1/projects`
- `repositories`, emits `depot.repositories`, reads `/v1/repositories`
- `deployments`, emits `depot.deployments`, reads `/v1/deployments`
- `audit_events`, emits `depot.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/depot ./internal/sourceprojection -count=1`
- `make catalog-check`
