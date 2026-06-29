# Stoplight

Generated Source Runtime SDK scaffold for `stoplight`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/stoplight`
- Health endpoint: `/source-runtimes/health?source_id=stoplight`
- Source health receipt: `sources/stoplight/source_health_receipt.json`
- EvidenceCAS reference kind: `stoplight.evidence_cas_reference`

## Families

- `users`, emits `stoplight.users`, reads `/v1/users`
- `projects`, emits `stoplight.projects`, reads `/v1/projects`
- `repositories`, emits `stoplight.repositories`, reads `/v1/repositories`
- `deployments`, emits `stoplight.deployments`, reads `/v1/deployments`
- `audit_events`, emits `stoplight.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/stoplight ./internal/sourceprojection -count=1`
- `make catalog-check`
