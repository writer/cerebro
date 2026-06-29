# Opslevel

Generated Source Runtime SDK scaffold for `opslevel`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/opslevel`
- Health endpoint: `/source-runtimes/health?source_id=opslevel`
- Source health receipt: `sources/opslevel/source_health_receipt.json`
- EvidenceCAS reference kind: `opslevel.evidence_cas_reference`

## Families

- `users`, emits `opslevel.users`, reads `/v1/users`
- `projects`, emits `opslevel.projects`, reads `/v1/projects`
- `repositories`, emits `opslevel.repositories`, reads `/v1/repositories`
- `deployments`, emits `opslevel.deployments`, reads `/v1/deployments`
- `audit_events`, emits `opslevel.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/opslevel ./internal/sourceprojection -count=1`
- `make catalog-check`
