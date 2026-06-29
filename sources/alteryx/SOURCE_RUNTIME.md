# Alteryx

Generated Source Runtime SDK scaffold for `alteryx`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/alteryx`
- Health endpoint: `/source-runtimes/health?source_id=alteryx`
- Source health receipt: `sources/alteryx/source_health_receipt.json`
- EvidenceCAS reference kind: `alteryx.evidence_cas_reference`

## Families

- `users`, emits `alteryx.users`, reads `/v1/users`
- `accounts`, emits `alteryx.accounts`, reads `/v1/accounts`
- `records`, emits `alteryx.records`, reads `/v1/records`
- `policies`, emits `alteryx.policies`, reads `/v1/policies`
- `audit_events`, emits `alteryx.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/alteryx ./internal/sourceprojection -count=1`
- `make catalog-check`
