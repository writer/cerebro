# Cloudsmith

Generated Source Runtime SDK scaffold for `cloudsmith`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cloudsmith`
- Health endpoint: `/source-runtimes/health?source_id=cloudsmith`
- Source health receipt: `sources/cloudsmith/source_health_receipt.json`
- EvidenceCAS reference kind: `cloudsmith.evidence_cas_reference`

## Families

- `users`, emits `cloudsmith.users`, reads `/v1/users`
- `projects`, emits `cloudsmith.projects`, reads `/v1/projects`
- `repositories`, emits `cloudsmith.repositories`, reads `/v1/repositories`
- `deployments`, emits `cloudsmith.deployments`, reads `/v1/deployments`
- `audit_events`, emits `cloudsmith.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cloudsmith ./internal/sourceprojection -count=1`
- `make catalog-check`
