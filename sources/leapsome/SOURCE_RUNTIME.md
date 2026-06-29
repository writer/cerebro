# Leapsome

Generated Source Runtime SDK scaffold for `leapsome`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/leapsome`
- Health endpoint: `/source-runtimes/health?source_id=leapsome`
- Source health receipt: `sources/leapsome/source_health_receipt.json`
- EvidenceCAS reference kind: `leapsome.evidence_cas_reference`

## Families

- `users`, emits `leapsome.users`, reads `/v1/users`
- `accounts`, emits `leapsome.accounts`, reads `/v1/accounts`
- `records`, emits `leapsome.records`, reads `/v1/records`
- `policies`, emits `leapsome.policies`, reads `/v1/policies`
- `audit_events`, emits `leapsome.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/leapsome ./internal/sourceprojection -count=1`
- `make catalog-check`
