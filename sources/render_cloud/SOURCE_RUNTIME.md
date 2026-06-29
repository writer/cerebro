# Render Cloud

Generated Source Runtime SDK scaffold for `render_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/render_cloud`
- Health endpoint: `/source-runtimes/health?source_id=render_cloud`
- Source health receipt: `sources/render_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `render_cloud.evidence_cas_reference`

## Families

- `users`, emits `render_cloud.users`, reads `/v1/users`
- `projects`, emits `render_cloud.projects`, reads `/v1/projects`
- `repositories`, emits `render_cloud.repositories`, reads `/v1/repositories`
- `deployments`, emits `render_cloud.deployments`, reads `/v1/deployments`
- `audit_events`, emits `render_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/render_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
