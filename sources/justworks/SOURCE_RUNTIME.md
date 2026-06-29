# Justworks

Generated Source Runtime SDK scaffold for `justworks`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/justworks`
- Health endpoint: `/source-runtimes/health?source_id=justworks`
- Source health receipt: `sources/justworks/source_health_receipt.json`
- EvidenceCAS reference kind: `justworks.evidence_cas_reference`

## Families

- `users`, emits `justworks.users`, reads `/v1/users`
- `accounts`, emits `justworks.accounts`, reads `/v1/accounts`
- `records`, emits `justworks.records`, reads `/v1/records`
- `policies`, emits `justworks.policies`, reads `/v1/policies`
- `audit_events`, emits `justworks.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/justworks ./internal/sourceprojection -count=1`
- `make catalog-check`
