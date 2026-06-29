# Procurify

Generated Source Runtime SDK scaffold for `procurify`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/procurify`
- Health endpoint: `/source-runtimes/health?source_id=procurify`
- Source health receipt: `sources/procurify/source_health_receipt.json`
- EvidenceCAS reference kind: `procurify.evidence_cas_reference`

## Families

- `users`, emits `procurify.users`, reads `/v1/users`
- `accounts`, emits `procurify.accounts`, reads `/v1/accounts`
- `records`, emits `procurify.records`, reads `/v1/records`
- `policies`, emits `procurify.policies`, reads `/v1/policies`
- `audit_events`, emits `procurify.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/procurify ./internal/sourceprojection -count=1`
- `make catalog-check`
