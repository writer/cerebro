# Kong Konnect

Generated Source Runtime SDK scaffold for `kong_konnect`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/kong_konnect`
- Health endpoint: `/source-runtimes/health?source_id=kong_konnect`
- Source health receipt: `sources/kong_konnect/source_health_receipt.json`
- EvidenceCAS reference kind: `kong_konnect.evidence_cas_reference`

## Families

- `users`, emits `kong_konnect.users`, reads `/v1/users`
- `projects`, emits `kong_konnect.projects`, reads `/v1/projects`
- `repositories`, emits `kong_konnect.repositories`, reads `/v1/repositories`
- `deployments`, emits `kong_konnect.deployments`, reads `/v1/deployments`
- `audit_events`, emits `kong_konnect.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/kong_konnect ./internal/sourceprojection -count=1`
- `make catalog-check`
