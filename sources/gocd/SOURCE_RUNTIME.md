# Gocd

Generated Source Runtime SDK scaffold for `gocd`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gocd`
- Health endpoint: `/source-runtimes/health?source_id=gocd`
- Source health receipt: `sources/gocd/source_health_receipt.json`
- EvidenceCAS reference kind: `gocd.evidence_cas_reference`

## Families

- `users`, emits `gocd.users`, reads `/v1/users`
- `projects`, emits `gocd.projects`, reads `/v1/projects`
- `repositories`, emits `gocd.repositories`, reads `/v1/repositories`
- `deployments`, emits `gocd.deployments`, reads `/v1/deployments`
- `audit_events`, emits `gocd.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/gocd ./internal/sourceprojection -count=1`
- `make catalog-check`
