# Platform Sh

Generated Source Runtime SDK scaffold for `platform_sh`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/platform_sh`
- Health endpoint: `/source-runtimes/health?source_id=platform_sh`
- Source health receipt: `sources/platform_sh/source_health_receipt.json`
- EvidenceCAS reference kind: `platform_sh.evidence_cas_reference`

## Families

- `users`, emits `platform_sh.users`, reads `/v1/users`
- `projects`, emits `platform_sh.projects`, reads `/v1/projects`
- `repositories`, emits `platform_sh.repositories`, reads `/v1/repositories`
- `deployments`, emits `platform_sh.deployments`, reads `/v1/deployments`
- `audit_events`, emits `platform_sh.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/platform_sh ./internal/sourceprojection -count=1`
- `make catalog-check`
