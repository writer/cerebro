# Firefly

Generated Source Runtime SDK scaffold for `firefly`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/firefly`
- Health endpoint: `/source-runtimes/health?source_id=firefly`
- Source health receipt: `sources/firefly/source_health_receipt.json`
- EvidenceCAS reference kind: `firefly.evidence_cas_reference`

## Families

- `users`, emits `firefly.users`, reads `/v1/users`
- `projects`, emits `firefly.projects`, reads `/v1/projects`
- `repositories`, emits `firefly.repositories`, reads `/v1/repositories`
- `deployments`, emits `firefly.deployments`, reads `/v1/deployments`
- `audit_events`, emits `firefly.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/firefly ./internal/sourceprojection -count=1`
- `make catalog-check`
