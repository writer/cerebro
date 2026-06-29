# Relativity One

Generated Source Runtime SDK scaffold for `relativity_one`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/relativity_one`
- Health endpoint: `/source-runtimes/health?source_id=relativity_one`
- Source health receipt: `sources/relativity_one/source_health_receipt.json`
- EvidenceCAS reference kind: `relativity_one.evidence_cas_reference`

## Families

- `users`, emits `relativity_one.users`, reads `/v1/users`
- `accounts`, emits `relativity_one.accounts`, reads `/v1/accounts`
- `records`, emits `relativity_one.records`, reads `/v1/records`
- `policies`, emits `relativity_one.policies`, reads `/v1/policies`
- `audit_events`, emits `relativity_one.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/relativity_one ./internal/sourceprojection -count=1`
- `make catalog-check`
