# Chargify

Generated Source Runtime SDK scaffold for `chargify`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/chargify`
- Health endpoint: `/source-runtimes/health?source_id=chargify`
- Source health receipt: `sources/chargify/source_health_receipt.json`
- EvidenceCAS reference kind: `chargify.evidence_cas_reference`

## Families

- `users`, emits `chargify.users`, reads `/v1/users`
- `accounts`, emits `chargify.accounts`, reads `/v1/accounts`
- `records`, emits `chargify.records`, reads `/v1/records`
- `policies`, emits `chargify.policies`, reads `/v1/policies`
- `audit_events`, emits `chargify.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/chargify ./internal/sourceprojection -count=1`
- `make catalog-check`
