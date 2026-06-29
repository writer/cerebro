# Readme

Generated Source Runtime SDK scaffold for `readme`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/readme`
- Health endpoint: `/source-runtimes/health?source_id=readme`
- Source health receipt: `sources/readme/source_health_receipt.json`
- EvidenceCAS reference kind: `readme.evidence_cas_reference`

## Families

- `users`, emits `readme.users`, reads `/v1/users`
- `projects`, emits `readme.projects`, reads `/v1/projects`
- `repositories`, emits `readme.repositories`, reads `/v1/repositories`
- `deployments`, emits `readme.deployments`, reads `/v1/deployments`
- `audit_events`, emits `readme.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/readme ./internal/sourceprojection -count=1`
- `make catalog-check`
