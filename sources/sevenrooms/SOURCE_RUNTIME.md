# Sevenrooms

Generated Source Runtime SDK scaffold for `sevenrooms`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sevenrooms`
- Health endpoint: `/source-runtimes/health?source_id=sevenrooms`
- Source health receipt: `sources/sevenrooms/source_health_receipt.json`
- EvidenceCAS reference kind: `sevenrooms.evidence_cas_reference`

## Families

- `users`, emits `sevenrooms.users`, reads `/v1/users`
- `accounts`, emits `sevenrooms.accounts`, reads `/v1/accounts`
- `records`, emits `sevenrooms.records`, reads `/v1/records`
- `policies`, emits `sevenrooms.policies`, reads `/v1/policies`
- `audit_events`, emits `sevenrooms.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sevenrooms ./internal/sourceprojection -count=1`
- `make catalog-check`
