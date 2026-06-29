# Quay

Generated Source Runtime SDK scaffold for `quay`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/quay`
- Health endpoint: `/source-runtimes/health?source_id=quay`
- Source health receipt: `sources/quay/source_health_receipt.json`
- EvidenceCAS reference kind: `quay.evidence_cas_reference`

## Families

- `users`, emits `quay.users`, reads `/v1/users`
- `projects`, emits `quay.projects`, reads `/v1/projects`
- `repositories`, emits `quay.repositories`, reads `/v1/repositories`
- `deployments`, emits `quay.deployments`, reads `/v1/deployments`
- `audit_events`, emits `quay.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/quay ./internal/sourceprojection -count=1`
- `make catalog-check`
