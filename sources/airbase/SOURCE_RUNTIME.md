# Airbase

Generated Source Runtime SDK scaffold for `airbase`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/airbase`
- Health endpoint: `/source-runtimes/health?source_id=airbase`
- Source health receipt: `sources/airbase/source_health_receipt.json`
- EvidenceCAS reference kind: `airbase.evidence_cas_reference`

## Families

- `users`, emits `airbase.users`, reads `/v1/users`
- `accounts`, emits `airbase.accounts`, reads `/v1/accounts`
- `records`, emits `airbase.records`, reads `/v1/records`
- `policies`, emits `airbase.policies`, reads `/v1/policies`
- `audit_events`, emits `airbase.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/airbase ./internal/sourceprojection -count=1`
- `make catalog-check`
