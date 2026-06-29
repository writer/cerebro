# Mulesoft Anypoint

Generated Source Runtime SDK scaffold for `mulesoft_anypoint`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mulesoft_anypoint`
- Health endpoint: `/source-runtimes/health?source_id=mulesoft_anypoint`
- Source health receipt: `sources/mulesoft_anypoint/source_health_receipt.json`
- EvidenceCAS reference kind: `mulesoft_anypoint.evidence_cas_reference`

## Families

- `users`, emits `mulesoft_anypoint.users`, reads `/v1/users`
- `projects`, emits `mulesoft_anypoint.projects`, reads `/v1/projects`
- `repositories`, emits `mulesoft_anypoint.repositories`, reads `/v1/repositories`
- `deployments`, emits `mulesoft_anypoint.deployments`, reads `/v1/deployments`
- `audit_events`, emits `mulesoft_anypoint.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/mulesoft_anypoint ./internal/sourceprojection -count=1`
- `make catalog-check`
