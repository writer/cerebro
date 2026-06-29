# Forethought

Generated Source Runtime SDK scaffold for `forethought`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/forethought`
- Health endpoint: `/source-runtimes/health?source_id=forethought`
- Source health receipt: `sources/forethought/source_health_receipt.json`
- EvidenceCAS reference kind: `forethought.evidence_cas_reference`

## Families

- `users`, emits `forethought.users`, reads `/v1/users`
- `accounts`, emits `forethought.accounts`, reads `/v1/accounts`
- `records`, emits `forethought.records`, reads `/v1/records`
- `policies`, emits `forethought.policies`, reads `/v1/policies`
- `audit_events`, emits `forethought.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/forethought ./internal/sourceprojection -count=1`
- `make catalog-check`
