# Azure DevOps

Generated Source Runtime SDK scaffold for `azure_devops`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/azure_devops`
- Health endpoint: `/source-runtimes/health?source_id=azure_devops`
- Source health receipt: `sources/azure_devops/source_health_receipt.json`
- EvidenceCAS reference kind: `azure_devops.evidence_cas_reference`

## Families

- `repositories`, emits `azure_devops.repositories`, reads `/v1/repositories`
- `users`, emits `azure_devops.users`, reads `/v1/users`
- `audit_events`, emits `azure_devops.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/azure_devops ./internal/sourceprojection -count=1`
- `make catalog-check`
