# Vitally

Generated Source Runtime SDK scaffold for `vitally`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/vitally`
- Health endpoint: `/source-runtimes/health?source_id=vitally`
- Source health receipt: `sources/vitally/source_health_receipt.json`
- EvidenceCAS reference kind: `vitally.evidence_cas_reference`

## Families

- `users`, emits `vitally.users`, reads `/v1/users`
- `accounts`, emits `vitally.accounts`, reads `/v1/accounts`
- `records`, emits `vitally.records`, reads `/v1/records`
- `policies`, emits `vitally.policies`, reads `/v1/policies`
- `audit_events`, emits `vitally.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/vitally ./internal/sourceprojection -count=1`
- `make catalog-check`
