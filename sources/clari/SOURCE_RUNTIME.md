# Clari

Generated Source Runtime SDK scaffold for `clari`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/clari`
- Health endpoint: `/source-runtimes/health?source_id=clari`
- Source health receipt: `sources/clari/source_health_receipt.json`
- EvidenceCAS reference kind: `clari.evidence_cas_reference`

## Families

- `users`, emits `clari.users`, reads `/v1/users`
- `accounts`, emits `clari.accounts`, reads `/v1/accounts`
- `records`, emits `clari.records`, reads `/v1/records`
- `policies`, emits `clari.policies`, reads `/v1/policies`
- `audit_events`, emits `clari.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/clari ./internal/sourceprojection -count=1`
- `make catalog-check`
