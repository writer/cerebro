# Thoughtspot

Generated Source Runtime SDK scaffold for `thoughtspot`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/thoughtspot`
- Health endpoint: `/source-runtimes/health?source_id=thoughtspot`
- Source health receipt: `sources/thoughtspot/source_health_receipt.json`
- EvidenceCAS reference kind: `thoughtspot.evidence_cas_reference`

## Families

- `users`, emits `thoughtspot.users`, reads `/v1/users`
- `accounts`, emits `thoughtspot.accounts`, reads `/v1/accounts`
- `records`, emits `thoughtspot.records`, reads `/v1/records`
- `policies`, emits `thoughtspot.policies`, reads `/v1/policies`
- `audit_events`, emits `thoughtspot.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/thoughtspot ./internal/sourceprojection -count=1`
- `make catalog-check`
