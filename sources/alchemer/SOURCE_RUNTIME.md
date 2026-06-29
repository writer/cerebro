# Alchemer

Generated Source Runtime SDK scaffold for `alchemer`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/alchemer`
- Health endpoint: `/source-runtimes/health?source_id=alchemer`
- Source health receipt: `sources/alchemer/source_health_receipt.json`
- EvidenceCAS reference kind: `alchemer.evidence_cas_reference`

## Families

- `users`, emits `alchemer.users`, reads `/v1/users`
- `accounts`, emits `alchemer.accounts`, reads `/v1/accounts`
- `records`, emits `alchemer.records`, reads `/v1/records`
- `policies`, emits `alchemer.policies`, reads `/v1/policies`
- `audit_events`, emits `alchemer.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/alchemer ./internal/sourceprojection -count=1`
- `make catalog-check`
