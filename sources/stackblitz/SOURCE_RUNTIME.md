# Stackblitz

Generated Source Runtime SDK scaffold for `stackblitz`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/stackblitz`
- Health endpoint: `/source-runtimes/health?source_id=stackblitz`
- Source health receipt: `sources/stackblitz/source_health_receipt.json`
- EvidenceCAS reference kind: `stackblitz.evidence_cas_reference`

## Families

- `users`, emits `stackblitz.users`, reads `/v1/users`
- `projects`, emits `stackblitz.projects`, reads `/v1/projects`
- `repositories`, emits `stackblitz.repositories`, reads `/v1/repositories`
- `deployments`, emits `stackblitz.deployments`, reads `/v1/deployments`
- `audit_events`, emits `stackblitz.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/stackblitz ./internal/sourceprojection -count=1`
- `make catalog-check`
