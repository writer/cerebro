# Browserstack

Generated Source Runtime SDK scaffold for `browserstack`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/browserstack`
- Health endpoint: `/source-runtimes/health?source_id=browserstack`
- Source health receipt: `sources/browserstack/source_health_receipt.json`
- EvidenceCAS reference kind: `browserstack.evidence_cas_reference`

## Families

- `users`, emits `browserstack.users`, reads `/v1/users`
- `projects`, emits `browserstack.projects`, reads `/v1/projects`
- `repositories`, emits `browserstack.repositories`, reads `/v1/repositories`
- `deployments`, emits `browserstack.deployments`, reads `/v1/deployments`
- `audit_events`, emits `browserstack.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/browserstack ./internal/sourceprojection -count=1`
- `make catalog-check`
