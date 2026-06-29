# Codacy

Generated Source Runtime SDK scaffold for `codacy`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/codacy`
- Health endpoint: `/source-runtimes/health?source_id=codacy`
- Source health receipt: `sources/codacy/source_health_receipt.json`
- EvidenceCAS reference kind: `codacy.evidence_cas_reference`

## Families

- `users`, emits `codacy.users`, reads `/v1/users`
- `projects`, emits `codacy.projects`, reads `/v1/projects`
- `repositories`, emits `codacy.repositories`, reads `/v1/repositories`
- `deployments`, emits `codacy.deployments`, reads `/v1/deployments`
- `audit_events`, emits `codacy.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/codacy ./internal/sourceprojection -count=1`
- `make catalog-check`
