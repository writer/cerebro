# Aha

Generated Source Runtime SDK scaffold for `aha`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/aha`
- Health endpoint: `/source-runtimes/health?source_id=aha`
- Source health receipt: `sources/aha/source_health_receipt.json`
- EvidenceCAS reference kind: `aha.evidence_cas_reference`

## Families

- `users`, emits `aha.users`, reads `/v1/users`
- `projects`, emits `aha.projects`, reads `/v1/projects`
- `repositories`, emits `aha.repositories`, reads `/v1/repositories`
- `deployments`, emits `aha.deployments`, reads `/v1/deployments`
- `audit_events`, emits `aha.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/aha ./internal/sourceprojection -count=1`
- `make catalog-check`
