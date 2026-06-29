# Coder Cloud

Generated Source Runtime SDK scaffold for `coder_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/coder_cloud`
- Health endpoint: `/source-runtimes/health?source_id=coder_cloud`
- Source health receipt: `sources/coder_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `coder_cloud.evidence_cas_reference`

## Families

- `users`, emits `coder_cloud.users`, reads `/v1/users`
- `projects`, emits `coder_cloud.projects`, reads `/v1/projects`
- `repositories`, emits `coder_cloud.repositories`, reads `/v1/repositories`
- `deployments`, emits `coder_cloud.deployments`, reads `/v1/deployments`
- `audit_events`, emits `coder_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/coder_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
