# Perfecto

Generated Source Runtime SDK scaffold for `perfecto`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/perfecto`
- Health endpoint: `/source-runtimes/health?source_id=perfecto`
- Source health receipt: `sources/perfecto/source_health_receipt.json`
- EvidenceCAS reference kind: `perfecto.evidence_cas_reference`

## Families

- `users`, emits `perfecto.users`, reads `/v1/users`
- `projects`, emits `perfecto.projects`, reads `/v1/projects`
- `repositories`, emits `perfecto.repositories`, reads `/v1/repositories`
- `deployments`, emits `perfecto.deployments`, reads `/v1/deployments`
- `audit_events`, emits `perfecto.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/perfecto ./internal/sourceprojection -count=1`
- `make catalog-check`
