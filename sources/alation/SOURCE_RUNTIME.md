# Alation

Generated Source Runtime SDK scaffold for `alation`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/alation`
- Health endpoint: `/source-runtimes/health?source_id=alation`
- Source health receipt: `sources/alation/source_health_receipt.json`
- EvidenceCAS reference kind: `alation.evidence_cas_reference`

## Families

- `users`, emits `alation.users`, reads `/v1/users`
- `accounts`, emits `alation.accounts`, reads `/v1/accounts`
- `records`, emits `alation.records`, reads `/v1/records`
- `policies`, emits `alation.policies`, reads `/v1/policies`
- `audit_events`, emits `alation.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/alation ./internal/sourceprojection -count=1`
- `make catalog-check`
