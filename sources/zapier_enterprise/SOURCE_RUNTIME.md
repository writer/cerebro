# Zapier Enterprise

Generated Source Runtime SDK scaffold for `zapier_enterprise`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zapier_enterprise`
- Health endpoint: `/source-runtimes/health?source_id=zapier_enterprise`
- Source health receipt: `sources/zapier_enterprise/source_health_receipt.json`
- EvidenceCAS reference kind: `zapier_enterprise.evidence_cas_reference`

## Families

- `users`, emits `zapier_enterprise.users`, reads `/v1/users`
- `projects`, emits `zapier_enterprise.projects`, reads `/v1/projects`
- `repositories`, emits `zapier_enterprise.repositories`, reads `/v1/repositories`
- `deployments`, emits `zapier_enterprise.deployments`, reads `/v1/deployments`
- `audit_events`, emits `zapier_enterprise.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zapier_enterprise ./internal/sourceprojection -count=1`
- `make catalog-check`
