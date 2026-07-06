# Airtable

Provider-verified Source Runtime SDK for `airtable`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/airtable`
- Health endpoint: `/source-runtimes/health?source_id=airtable`
- Source health receipt: `sources/airtable/source_health_receipt.json`
- EvidenceCAS reference kind: `airtable.evidence_cas_reference`

## Families

- `bases`, emits `airtable.bases`, reads `GET /v0/meta/bases`
- `users`, emits `airtable.users`, reads `GET /v0/meta/enterpriseAccounts/{enterpriseAccountId}/users`
- `audit_events`, emits `airtable.audit_events`, reads `GET /v0/meta/enterpriseAccounts/{enterpriseAccountId}/auditLogEvents`

## Tests

- `go test ./sources/airtable ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/airtable/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
