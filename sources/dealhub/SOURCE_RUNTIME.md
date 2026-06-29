# Dealhub

Generated Source Runtime SDK scaffold for `dealhub`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/dealhub`
- Health endpoint: `/source-runtimes/health?source_id=dealhub`
- Source health receipt: `sources/dealhub/source_health_receipt.json`
- EvidenceCAS reference kind: `dealhub.evidence_cas_reference`

## Families

- `users`, emits `dealhub.users`, reads `/v1/users`
- `accounts`, emits `dealhub.accounts`, reads `/v1/accounts`
- `records`, emits `dealhub.records`, reads `/v1/records`
- `policies`, emits `dealhub.policies`, reads `/v1/policies`
- `audit_events`, emits `dealhub.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/dealhub ./internal/sourceprojection -count=1`
- `make catalog-check`
