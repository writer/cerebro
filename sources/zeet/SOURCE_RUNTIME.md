# Zeet

Generated Source Runtime SDK scaffold for `zeet`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zeet`
- Health endpoint: `/source-runtimes/health?source_id=zeet`
- Source health receipt: `sources/zeet/source_health_receipt.json`
- EvidenceCAS reference kind: `zeet.evidence_cas_reference`

## Families

- `users`, emits `zeet.users`, reads `/v1/users`
- `projects`, emits `zeet.projects`, reads `/v1/projects`
- `repositories`, emits `zeet.repositories`, reads `/v1/repositories`
- `deployments`, emits `zeet.deployments`, reads `/v1/deployments`
- `audit_events`, emits `zeet.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zeet ./internal/sourceprojection -count=1`
- `make catalog-check`
