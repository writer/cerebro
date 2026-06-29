# Chorus

Generated Source Runtime SDK scaffold for `chorus`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/chorus`
- Health endpoint: `/source-runtimes/health?source_id=chorus`
- Source health receipt: `sources/chorus/source_health_receipt.json`
- EvidenceCAS reference kind: `chorus.evidence_cas_reference`

## Families

- `users`, emits `chorus.users`, reads `/v1/users`
- `accounts`, emits `chorus.accounts`, reads `/v1/accounts`
- `records`, emits `chorus.records`, reads `/v1/records`
- `policies`, emits `chorus.policies`, reads `/v1/policies`
- `audit_events`, emits `chorus.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/chorus ./internal/sourceprojection -count=1`
- `make catalog-check`
