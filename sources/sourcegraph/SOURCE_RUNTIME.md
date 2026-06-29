# Sourcegraph

Generated Source Runtime SDK scaffold for `sourcegraph`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sourcegraph`
- Health endpoint: `/source-runtimes/health?source_id=sourcegraph`
- Source health receipt: `sources/sourcegraph/source_health_receipt.json`
- EvidenceCAS reference kind: `sourcegraph.evidence_cas_reference`

## Families

- `users`, emits `sourcegraph.users`, reads `/v1/users`
- `projects`, emits `sourcegraph.projects`, reads `/v1/projects`
- `repositories`, emits `sourcegraph.repositories`, reads `/v1/repositories`
- `deployments`, emits `sourcegraph.deployments`, reads `/v1/deployments`
- `audit_events`, emits `sourcegraph.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sourcegraph ./internal/sourceprojection -count=1`
- `make catalog-check`
