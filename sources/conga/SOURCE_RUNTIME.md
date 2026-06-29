# Conga

Generated Source Runtime SDK scaffold for `conga`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/conga`
- Health endpoint: `/source-runtimes/health?source_id=conga`
- Source health receipt: `sources/conga/source_health_receipt.json`
- EvidenceCAS reference kind: `conga.evidence_cas_reference`

## Families

- `users`, emits `conga.users`, reads `/v1/users`
- `accounts`, emits `conga.accounts`, reads `/v1/accounts`
- `records`, emits `conga.records`, reads `/v1/records`
- `policies`, emits `conga.policies`, reads `/v1/policies`
- `audit_events`, emits `conga.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/conga ./internal/sourceprojection -count=1`
- `make catalog-check`
