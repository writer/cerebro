# UKG Pro

Generated Source Runtime SDK scaffold for `ukg_pro`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ukg_pro`
- Health endpoint: `/source-runtimes/health?source_id=ukg_pro`
- Source health receipt: `sources/ukg_pro/source_health_receipt.json`
- EvidenceCAS reference kind: `ukg_pro.evidence_cas_reference`

## Families

- `users`, emits `ukg_pro.users`, reads `/v1/users`
- `accounts`, emits `ukg_pro.accounts`, reads `/v1/accounts`
- `records`, emits `ukg_pro.records`, reads `/v1/records`
- `policies`, emits `ukg_pro.policies`, reads `/v1/policies`
- `audit_events`, emits `ukg_pro.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/ukg_pro ./internal/sourceprojection -count=1`
- `make catalog-check`
