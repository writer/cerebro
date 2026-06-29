# Activtrak

Generated Source Runtime SDK scaffold for `activtrak`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/activtrak`
- Health endpoint: `/source-runtimes/health?source_id=activtrak`
- Source health receipt: `sources/activtrak/source_health_receipt.json`
- EvidenceCAS reference kind: `activtrak.evidence_cas_reference`

## Families

- `users`, emits `activtrak.users`, reads `/v1/users`
- `accounts`, emits `activtrak.accounts`, reads `/v1/accounts`
- `records`, emits `activtrak.records`, reads `/v1/records`
- `policies`, emits `activtrak.policies`, reads `/v1/policies`
- `audit_events`, emits `activtrak.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/activtrak ./internal/sourceprojection -count=1`
- `make catalog-check`
