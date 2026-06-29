# Rudderstack

Generated Source Runtime SDK scaffold for `rudderstack`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/rudderstack`
- Health endpoint: `/source-runtimes/health?source_id=rudderstack`
- Source health receipt: `sources/rudderstack/source_health_receipt.json`
- EvidenceCAS reference kind: `rudderstack.evidence_cas_reference`

## Families

- `users`, emits `rudderstack.users`, reads `/v1/users`
- `accounts`, emits `rudderstack.accounts`, reads `/v1/accounts`
- `records`, emits `rudderstack.records`, reads `/v1/records`
- `policies`, emits `rudderstack.policies`, reads `/v1/policies`
- `audit_events`, emits `rudderstack.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/rudderstack ./internal/sourceprojection -count=1`
- `make catalog-check`
