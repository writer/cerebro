# Rally

Generated Source Runtime SDK scaffold for `rally`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/rally`
- Health endpoint: `/source-runtimes/health?source_id=rally`
- Source health receipt: `sources/rally/source_health_receipt.json`
- EvidenceCAS reference kind: `rally.evidence_cas_reference`

## Families

- `users`, emits `rally.users`, reads `/v1/users`
- `projects`, emits `rally.projects`, reads `/v1/projects`
- `repositories`, emits `rally.repositories`, reads `/v1/repositories`
- `deployments`, emits `rally.deployments`, reads `/v1/deployments`
- `audit_events`, emits `rally.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/rally ./internal/sourceprojection -count=1`
- `make catalog-check`
