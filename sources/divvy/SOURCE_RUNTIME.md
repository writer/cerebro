# Divvy

Generated Source Runtime SDK scaffold for `divvy`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/divvy`
- Health endpoint: `/source-runtimes/health?source_id=divvy`
- Source health receipt: `sources/divvy/source_health_receipt.json`
- EvidenceCAS reference kind: `divvy.evidence_cas_reference`

## Families

- `users`, emits `divvy.users`, reads `/v1/users`
- `accounts`, emits `divvy.accounts`, reads `/v1/accounts`
- `records`, emits `divvy.records`, reads `/v1/records`
- `policies`, emits `divvy.policies`, reads `/v1/policies`
- `audit_events`, emits `divvy.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/divvy ./internal/sourceprojection -count=1`
- `make catalog-check`
