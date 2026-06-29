# Appcircle

Generated Source Runtime SDK scaffold for `appcircle`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/appcircle`
- Health endpoint: `/source-runtimes/health?source_id=appcircle`
- Source health receipt: `sources/appcircle/source_health_receipt.json`
- EvidenceCAS reference kind: `appcircle.evidence_cas_reference`

## Families

- `users`, emits `appcircle.users`, reads `/v1/users`
- `projects`, emits `appcircle.projects`, reads `/v1/projects`
- `repositories`, emits `appcircle.repositories`, reads `/v1/repositories`
- `deployments`, emits `appcircle.deployments`, reads `/v1/deployments`
- `audit_events`, emits `appcircle.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/appcircle ./internal/sourceprojection -count=1`
- `make catalog-check`
