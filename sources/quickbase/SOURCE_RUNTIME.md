# Quickbase

Generated Source Runtime SDK scaffold for `quickbase`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/quickbase`
- Health endpoint: `/source-runtimes/health?source_id=quickbase`
- Source health receipt: `sources/quickbase/source_health_receipt.json`
- EvidenceCAS reference kind: `quickbase.evidence_cas_reference`

## Families

- `users`, emits `quickbase.users`, reads `/v1/users`
- `accounts`, emits `quickbase.accounts`, reads `/v1/accounts`
- `records`, emits `quickbase.records`, reads `/v1/records`
- `policies`, emits `quickbase.policies`, reads `/v1/policies`
- `audit_events`, emits `quickbase.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/quickbase ./internal/sourceprojection -count=1`
- `make catalog-check`
