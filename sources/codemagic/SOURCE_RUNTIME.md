# Codemagic

Generated Source Runtime SDK scaffold for `codemagic`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/codemagic`
- Health endpoint: `/source-runtimes/health?source_id=codemagic`
- Source health receipt: `sources/codemagic/source_health_receipt.json`
- EvidenceCAS reference kind: `codemagic.evidence_cas_reference`

## Families

- `users`, emits `codemagic.users`, reads `/v1/users`
- `projects`, emits `codemagic.projects`, reads `/v1/projects`
- `repositories`, emits `codemagic.repositories`, reads `/v1/repositories`
- `deployments`, emits `codemagic.deployments`, reads `/v1/deployments`
- `audit_events`, emits `codemagic.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/codemagic ./internal/sourceprojection -count=1`
- `make catalog-check`
