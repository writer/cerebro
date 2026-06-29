# Jfrog Xray

Generated Source Runtime SDK scaffold for `jfrog_xray`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/jfrog_xray`
- Health endpoint: `/source-runtimes/health?source_id=jfrog_xray`
- Source health receipt: `sources/jfrog_xray/source_health_receipt.json`
- EvidenceCAS reference kind: `jfrog_xray.evidence_cas_reference`

## Families

- `users`, emits `jfrog_xray.users`, reads `/v1/users`
- `projects`, emits `jfrog_xray.projects`, reads `/v1/projects`
- `repositories`, emits `jfrog_xray.repositories`, reads `/v1/repositories`
- `deployments`, emits `jfrog_xray.deployments`, reads `/v1/deployments`
- `audit_events`, emits `jfrog_xray.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/jfrog_xray ./internal/sourceprojection -count=1`
- `make catalog-check`
