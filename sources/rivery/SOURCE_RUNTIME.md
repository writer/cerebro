# Rivery

Generated Source Runtime SDK scaffold for `rivery`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/rivery`
- Health endpoint: `/source-runtimes/health?source_id=rivery`
- Source health receipt: `sources/rivery/source_health_receipt.json`
- EvidenceCAS reference kind: `rivery.evidence_cas_reference`

## Families

- `users`, emits `rivery.users`, reads `/v1/users`
- `accounts`, emits `rivery.accounts`, reads `/v1/accounts`
- `records`, emits `rivery.records`, reads `/v1/records`
- `policies`, emits `rivery.policies`, reads `/v1/policies`
- `audit_events`, emits `rivery.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/rivery ./internal/sourceprojection -count=1`
- `make catalog-check`
