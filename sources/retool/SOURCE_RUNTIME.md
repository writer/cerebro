# Retool

Generated Source Runtime SDK scaffold for `retool`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/retool`
- Health endpoint: `/source-runtimes/health?source_id=retool`
- Source health receipt: `sources/retool/source_health_receipt.json`
- EvidenceCAS reference kind: `retool.evidence_cas_reference`

## Families

- `users`, emits `retool.users`, reads `/v1/users`
- `projects`, emits `retool.projects`, reads `/v1/projects`
- `repositories`, emits `retool.repositories`, reads `/v1/repositories`
- `deployments`, emits `retool.deployments`, reads `/v1/deployments`
- `audit_events`, emits `retool.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/retool ./internal/sourceprojection -count=1`
- `make catalog-check`
