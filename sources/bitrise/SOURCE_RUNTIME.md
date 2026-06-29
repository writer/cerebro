# Bitrise

Generated Source Runtime SDK scaffold for `bitrise`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bitrise`
- Health endpoint: `/source-runtimes/health?source_id=bitrise`
- Source health receipt: `sources/bitrise/source_health_receipt.json`
- EvidenceCAS reference kind: `bitrise.evidence_cas_reference`

## Families

- `users`, emits `bitrise.users`, reads `/v1/users`
- `projects`, emits `bitrise.projects`, reads `/v1/projects`
- `repositories`, emits `bitrise.repositories`, reads `/v1/repositories`
- `deployments`, emits `bitrise.deployments`, reads `/v1/deployments`
- `audit_events`, emits `bitrise.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/bitrise ./internal/sourceprojection -count=1`
- `make catalog-check`
