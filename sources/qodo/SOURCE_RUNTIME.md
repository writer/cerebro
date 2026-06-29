# Qodo

Generated Source Runtime SDK scaffold for `qodo`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/qodo`
- Health endpoint: `/source-runtimes/health?source_id=qodo`
- Source health receipt: `sources/qodo/source_health_receipt.json`
- EvidenceCAS reference kind: `qodo.evidence_cas_reference`

## Families

- `users`, emits `qodo.users`, reads `/v1/users`
- `projects`, emits `qodo.projects`, reads `/v1/projects`
- `repositories`, emits `qodo.repositories`, reads `/v1/repositories`
- `deployments`, emits `qodo.deployments`, reads `/v1/deployments`
- `audit_events`, emits `qodo.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/qodo ./internal/sourceprojection -count=1`
- `make catalog-check`
