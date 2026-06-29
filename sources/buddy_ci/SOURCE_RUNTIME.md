# Buddy CI

Generated Source Runtime SDK scaffold for `buddy_ci`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/buddy_ci`
- Health endpoint: `/source-runtimes/health?source_id=buddy_ci`
- Source health receipt: `sources/buddy_ci/source_health_receipt.json`
- EvidenceCAS reference kind: `buddy_ci.evidence_cas_reference`

## Families

- `users`, emits `buddy_ci.users`, reads `/v1/users`
- `projects`, emits `buddy_ci.projects`, reads `/v1/projects`
- `repositories`, emits `buddy_ci.repositories`, reads `/v1/repositories`
- `deployments`, emits `buddy_ci.deployments`, reads `/v1/deployments`
- `audit_events`, emits `buddy_ci.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/buddy_ci ./internal/sourceprojection -count=1`
- `make catalog-check`
