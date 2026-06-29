# Matillion

Generated Source Runtime SDK scaffold for `matillion`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/matillion`
- Health endpoint: `/source-runtimes/health?source_id=matillion`
- Source health receipt: `sources/matillion/source_health_receipt.json`
- EvidenceCAS reference kind: `matillion.evidence_cas_reference`

## Families

- `users`, emits `matillion.users`, reads `/v1/users`
- `accounts`, emits `matillion.accounts`, reads `/v1/accounts`
- `records`, emits `matillion.records`, reads `/v1/records`
- `policies`, emits `matillion.policies`, reads `/v1/policies`
- `audit_events`, emits `matillion.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/matillion ./internal/sourceprojection -count=1`
- `make catalog-check`
