# Workato

Generated Source Runtime SDK scaffold for `workato`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/workato`
- Health endpoint: `/source-runtimes/health?source_id=workato`
- Source health receipt: `sources/workato/source_health_receipt.json`
- EvidenceCAS reference kind: `workato.evidence_cas_reference`

## Families

- `users`, emits `workato.users`, reads `/v1/users`
- `projects`, emits `workato.projects`, reads `/v1/projects`
- `repositories`, emits `workato.repositories`, reads `/v1/repositories`
- `deployments`, emits `workato.deployments`, reads `/v1/deployments`
- `audit_events`, emits `workato.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/workato ./internal/sourceprojection -count=1`
- `make catalog-check`
