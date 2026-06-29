# Gitpod

Generated Source Runtime SDK scaffold for `gitpod`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gitpod`
- Health endpoint: `/source-runtimes/health?source_id=gitpod`
- Source health receipt: `sources/gitpod/source_health_receipt.json`
- EvidenceCAS reference kind: `gitpod.evidence_cas_reference`

## Families

- `users`, emits `gitpod.users`, reads `/v1/users`
- `projects`, emits `gitpod.projects`, reads `/v1/projects`
- `repositories`, emits `gitpod.repositories`, reads `/v1/repositories`
- `deployments`, emits `gitpod.deployments`, reads `/v1/deployments`
- `audit_events`, emits `gitpod.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/gitpod ./internal/sourceprojection -count=1`
- `make catalog-check`
