# Freshsales

Generated Source Runtime SDK scaffold for `freshsales`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/freshsales`
- Health endpoint: `/source-runtimes/health?source_id=freshsales`
- Source health receipt: `sources/freshsales/source_health_receipt.json`
- EvidenceCAS reference kind: `freshsales.evidence_cas_reference`

## Families

- `users`, emits `freshsales.users`, reads `/v1/users`
- `accounts`, emits `freshsales.accounts`, reads `/v1/accounts`
- `records`, emits `freshsales.records`, reads `/v1/records`
- `policies`, emits `freshsales.policies`, reads `/v1/policies`
- `audit_events`, emits `freshsales.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/freshsales ./internal/sourceprojection -count=1`
- `make catalog-check`
