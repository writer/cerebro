# Testim

Generated Source Runtime SDK scaffold for `testim`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/testim`
- Health endpoint: `/source-runtimes/health?source_id=testim`
- Source health receipt: `sources/testim/source_health_receipt.json`
- EvidenceCAS reference kind: `testim.evidence_cas_reference`

## Families

- `users`, emits `testim.users`, reads `/v1/users`
- `projects`, emits `testim.projects`, reads `/v1/projects`
- `repositories`, emits `testim.repositories`, reads `/v1/repositories`
- `deployments`, emits `testim.deployments`, reads `/v1/deployments`
- `audit_events`, emits `testim.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/testim ./internal/sourceprojection -count=1`
- `make catalog-check`
