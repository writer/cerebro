# Hibob

Generated Source Runtime SDK scaffold for `hibob`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hibob`
- Health endpoint: `/source-runtimes/health?source_id=hibob`
- Source health receipt: `sources/hibob/source_health_receipt.json`
- EvidenceCAS reference kind: `hibob.evidence_cas_reference`

## Families

- `users`, emits `hibob.users`, reads `/v1/users`
- `accounts`, emits `hibob.accounts`, reads `/v1/accounts`
- `records`, emits `hibob.records`, reads `/v1/records`
- `policies`, emits `hibob.policies`, reads `/v1/policies`
- `audit_events`, emits `hibob.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/hibob ./internal/sourceprojection -count=1`
- `make catalog-check`
