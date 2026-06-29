# Shorebird

Generated Source Runtime SDK scaffold for `shorebird`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/shorebird`
- Health endpoint: `/source-runtimes/health?source_id=shorebird`
- Source health receipt: `sources/shorebird/source_health_receipt.json`
- EvidenceCAS reference kind: `shorebird.evidence_cas_reference`

## Families

- `users`, emits `shorebird.users`, reads `/v1/users`
- `projects`, emits `shorebird.projects`, reads `/v1/projects`
- `repositories`, emits `shorebird.repositories`, reads `/v1/repositories`
- `deployments`, emits `shorebird.deployments`, reads `/v1/deployments`
- `audit_events`, emits `shorebird.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/shorebird ./internal/sourceprojection -count=1`
- `make catalog-check`
