# Infisical

Generated Source Runtime SDK scaffold for `infisical`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/infisical`
- Health endpoint: `/source-runtimes/health?source_id=infisical`
- Source health receipt: `sources/infisical/source_health_receipt.json`
- EvidenceCAS reference kind: `infisical.evidence_cas_reference`

## Families

- `users`, emits `infisical.users`, reads `/v1/users`
- `projects`, emits `infisical.projects`, reads `/v1/projects`
- `repositories`, emits `infisical.repositories`, reads `/v1/repositories`
- `deployments`, emits `infisical.deployments`, reads `/v1/deployments`
- `audit_events`, emits `infisical.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/infisical ./internal/sourceprojection -count=1`
- `make catalog-check`
