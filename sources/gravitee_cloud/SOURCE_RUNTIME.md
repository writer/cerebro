# Gravitee Cloud

Generated Source Runtime SDK scaffold for `gravitee_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gravitee_cloud`
- Health endpoint: `/source-runtimes/health?source_id=gravitee_cloud`
- Source health receipt: `sources/gravitee_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `gravitee_cloud.evidence_cas_reference`

## Families

- `users`, emits `gravitee_cloud.users`, reads `/v1/users`
- `projects`, emits `gravitee_cloud.projects`, reads `/v1/projects`
- `repositories`, emits `gravitee_cloud.repositories`, reads `/v1/repositories`
- `deployments`, emits `gravitee_cloud.deployments`, reads `/v1/deployments`
- `audit_events`, emits `gravitee_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/gravitee_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
