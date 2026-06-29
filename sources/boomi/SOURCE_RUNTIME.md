# Boomi

Generated Source Runtime SDK scaffold for `boomi`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/boomi`
- Health endpoint: `/source-runtimes/health?source_id=boomi`
- Source health receipt: `sources/boomi/source_health_receipt.json`
- EvidenceCAS reference kind: `boomi.evidence_cas_reference`

## Families

- `users`, emits `boomi.users`, reads `/v1/users`
- `projects`, emits `boomi.projects`, reads `/v1/projects`
- `repositories`, emits `boomi.repositories`, reads `/v1/repositories`
- `deployments`, emits `boomi.deployments`, reads `/v1/deployments`
- `audit_events`, emits `boomi.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/boomi ./internal/sourceprojection -count=1`
- `make catalog-check`
