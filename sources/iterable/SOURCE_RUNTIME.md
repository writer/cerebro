# Iterable

Generated Source Runtime SDK scaffold for `iterable`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/iterable`
- Health endpoint: `/source-runtimes/health?source_id=iterable`
- Source health receipt: `sources/iterable/source_health_receipt.json`
- EvidenceCAS reference kind: `iterable.evidence_cas_reference`

## Families

- `users`, emits `iterable.users`, reads `/v1/users`
- `accounts`, emits `iterable.accounts`, reads `/v1/accounts`
- `records`, emits `iterable.records`, reads `/v1/records`
- `policies`, emits `iterable.policies`, reads `/v1/policies`
- `audit_events`, emits `iterable.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/iterable ./internal/sourceprojection -count=1`
- `make catalog-check`
