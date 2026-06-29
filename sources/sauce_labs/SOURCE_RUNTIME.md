# Sauce Labs

Generated Source Runtime SDK scaffold for `sauce_labs`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sauce_labs`
- Health endpoint: `/source-runtimes/health?source_id=sauce_labs`
- Source health receipt: `sources/sauce_labs/source_health_receipt.json`
- EvidenceCAS reference kind: `sauce_labs.evidence_cas_reference`

## Families

- `users`, emits `sauce_labs.users`, reads `/v1/users`
- `projects`, emits `sauce_labs.projects`, reads `/v1/projects`
- `repositories`, emits `sauce_labs.repositories`, reads `/v1/repositories`
- `deployments`, emits `sauce_labs.deployments`, reads `/v1/deployments`
- `audit_events`, emits `sauce_labs.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sauce_labs ./internal/sourceprojection -count=1`
- `make catalog-check`
