# Spacelift

Generated Source Runtime SDK scaffold for `spacelift`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/spacelift`
- Health endpoint: `/source-runtimes/health?source_id=spacelift`
- Source health receipt: `sources/spacelift/source_health_receipt.json`
- EvidenceCAS reference kind: `spacelift.evidence_cas_reference`

## Families

- `users`, emits `spacelift.users`, reads `/v1/users`
- `projects`, emits `spacelift.projects`, reads `/v1/projects`
- `repositories`, emits `spacelift.repositories`, reads `/v1/repositories`
- `deployments`, emits `spacelift.deployments`, reads `/v1/deployments`
- `audit_events`, emits `spacelift.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/spacelift ./internal/sourceprojection -count=1`
- `make catalog-check`
