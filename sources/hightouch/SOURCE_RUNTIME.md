# Hightouch

Generated Source Runtime SDK scaffold for `hightouch`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hightouch`
- Health endpoint: `/source-runtimes/health?source_id=hightouch`
- Source health receipt: `sources/hightouch/source_health_receipt.json`
- EvidenceCAS reference kind: `hightouch.evidence_cas_reference`

## Families

- `users`, emits `hightouch.users`, reads `/v1/users`
- `accounts`, emits `hightouch.accounts`, reads `/v1/accounts`
- `records`, emits `hightouch.records`, reads `/v1/records`
- `policies`, emits `hightouch.policies`, reads `/v1/policies`
- `audit_events`, emits `hightouch.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/hightouch ./internal/sourceprojection -count=1`
- `make catalog-check`
