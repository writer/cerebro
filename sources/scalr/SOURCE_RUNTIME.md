# Scalr

Generated Source Runtime SDK scaffold for `scalr`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/scalr`
- Health endpoint: `/source-runtimes/health?source_id=scalr`
- Source health receipt: `sources/scalr/source_health_receipt.json`
- EvidenceCAS reference kind: `scalr.evidence_cas_reference`

## Families

- `users`, emits `scalr.users`, reads `/v1/users`
- `projects`, emits `scalr.projects`, reads `/v1/projects`
- `repositories`, emits `scalr.repositories`, reads `/v1/repositories`
- `deployments`, emits `scalr.deployments`, reads `/v1/deployments`
- `audit_events`, emits `scalr.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/scalr ./internal/sourceprojection -count=1`
- `make catalog-check`
