# Statsig

Generated Source Runtime SDK scaffold for `statsig`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/statsig`
- Health endpoint: `/source-runtimes/health?source_id=statsig`
- Source health receipt: `sources/statsig/source_health_receipt.json`
- EvidenceCAS reference kind: `statsig.evidence_cas_reference`

## Families

- `users`, emits `statsig.users`, reads `/v1/users`
- `projects`, emits `statsig.projects`, reads `/v1/projects`
- `repositories`, emits `statsig.repositories`, reads `/v1/repositories`
- `deployments`, emits `statsig.deployments`, reads `/v1/deployments`
- `audit_events`, emits `statsig.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/statsig ./internal/sourceprojection -count=1`
- `make catalog-check`
