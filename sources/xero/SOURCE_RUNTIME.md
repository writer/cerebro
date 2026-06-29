# Xero

Generated Source Runtime SDK scaffold for `xero`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/xero`
- Health endpoint: `/source-runtimes/health?source_id=xero`
- Source health receipt: `sources/xero/source_health_receipt.json`
- EvidenceCAS reference kind: `xero.evidence_cas_reference`

## Families

- `users`, emits `xero.users`, reads `/v1/users`
- `accounts`, emits `xero.accounts`, reads `/v1/accounts`
- `records`, emits `xero.records`, reads `/v1/records`
- `policies`, emits `xero.policies`, reads `/v1/policies`
- `audit_events`, emits `xero.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/xero ./internal/sourceprojection -count=1`
- `make catalog-check`
