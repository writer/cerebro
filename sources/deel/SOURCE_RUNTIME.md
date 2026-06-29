# Deel

Generated Source Runtime SDK scaffold for `deel`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/deel`
- Health endpoint: `/source-runtimes/health?source_id=deel`
- Source health receipt: `sources/deel/source_health_receipt.json`
- EvidenceCAS reference kind: `deel.evidence_cas_reference`

## Families

- `users`, emits `deel.users`, reads `/v1/users`
- `accounts`, emits `deel.accounts`, reads `/v1/accounts`
- `records`, emits `deel.records`, reads `/v1/records`
- `policies`, emits `deel.policies`, reads `/v1/policies`
- `audit_events`, emits `deel.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/deel ./internal/sourceprojection -count=1`
- `make catalog-check`
