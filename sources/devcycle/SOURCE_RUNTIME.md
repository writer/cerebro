# Devcycle

Generated Source Runtime SDK scaffold for `devcycle`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/devcycle`
- Health endpoint: `/source-runtimes/health?source_id=devcycle`
- Source health receipt: `sources/devcycle/source_health_receipt.json`
- EvidenceCAS reference kind: `devcycle.evidence_cas_reference`

## Families

- `users`, emits `devcycle.users`, reads `/v1/users`
- `projects`, emits `devcycle.projects`, reads `/v1/projects`
- `repositories`, emits `devcycle.repositories`, reads `/v1/repositories`
- `deployments`, emits `devcycle.deployments`, reads `/v1/deployments`
- `audit_events`, emits `devcycle.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/devcycle ./internal/sourceprojection -count=1`
- `make catalog-check`
