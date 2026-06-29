# Airfocus

Generated Source Runtime SDK scaffold for `airfocus`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/airfocus`
- Health endpoint: `/source-runtimes/health?source_id=airfocus`
- Source health receipt: `sources/airfocus/source_health_receipt.json`
- EvidenceCAS reference kind: `airfocus.evidence_cas_reference`

## Families

- `users`, emits `airfocus.users`, reads `/v1/users`
- `projects`, emits `airfocus.projects`, reads `/v1/projects`
- `repositories`, emits `airfocus.repositories`, reads `/v1/repositories`
- `deployments`, emits `airfocus.deployments`, reads `/v1/deployments`
- `audit_events`, emits `airfocus.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/airfocus ./internal/sourceprojection -count=1`
- `make catalog-check`
