# Fivetran

Generated Source Runtime SDK scaffold for `fivetran`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fivetran`
- Health endpoint: `/source-runtimes/health?source_id=fivetran`
- Source health receipt: `sources/fivetran/source_health_receipt.json`
- EvidenceCAS reference kind: `fivetran.evidence_cas_reference`

## Families

- `users`, emits `fivetran.users`, reads `/v1/users`
- `accounts`, emits `fivetran.accounts`, reads `/v1/accounts`
- `records`, emits `fivetran.records`, reads `/v1/records`
- `policies`, emits `fivetran.policies`, reads `/v1/policies`
- `audit_events`, emits `fivetran.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/fivetran ./internal/sourceprojection -count=1`
- `make catalog-check`
