# Applitools

Generated Source Runtime SDK scaffold for `applitools`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/applitools`
- Health endpoint: `/source-runtimes/health?source_id=applitools`
- Source health receipt: `sources/applitools/source_health_receipt.json`
- EvidenceCAS reference kind: `applitools.evidence_cas_reference`

## Families

- `users`, emits `applitools.users`, reads `/v1/users`
- `projects`, emits `applitools.projects`, reads `/v1/projects`
- `repositories`, emits `applitools.repositories`, reads `/v1/repositories`
- `deployments`, emits `applitools.deployments`, reads `/v1/deployments`
- `audit_events`, emits `applitools.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/applitools ./internal/sourceprojection -count=1`
- `make catalog-check`
