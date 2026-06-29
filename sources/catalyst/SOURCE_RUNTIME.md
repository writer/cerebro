# Catalyst

Generated Source Runtime SDK scaffold for `catalyst`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/catalyst`
- Health endpoint: `/source-runtimes/health?source_id=catalyst`
- Source health receipt: `sources/catalyst/source_health_receipt.json`
- EvidenceCAS reference kind: `catalyst.evidence_cas_reference`

## Families

- `users`, emits `catalyst.users`, reads `/v1/users`
- `accounts`, emits `catalyst.accounts`, reads `/v1/accounts`
- `records`, emits `catalyst.records`, reads `/v1/records`
- `policies`, emits `catalyst.policies`, reads `/v1/policies`
- `audit_events`, emits `catalyst.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/catalyst ./internal/sourceprojection -count=1`
- `make catalog-check`
