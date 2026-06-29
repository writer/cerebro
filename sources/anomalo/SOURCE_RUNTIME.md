# Anomalo

Generated Source Runtime SDK scaffold for `anomalo`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/anomalo`
- Health endpoint: `/source-runtimes/health?source_id=anomalo`
- Source health receipt: `sources/anomalo/source_health_receipt.json`
- EvidenceCAS reference kind: `anomalo.evidence_cas_reference`

## Families

- `users`, emits `anomalo.users`, reads `/v1/users`
- `accounts`, emits `anomalo.accounts`, reads `/v1/accounts`
- `records`, emits `anomalo.records`, reads `/v1/records`
- `policies`, emits `anomalo.policies`, reads `/v1/policies`
- `audit_events`, emits `anomalo.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/anomalo ./internal/sourceprojection -count=1`
- `make catalog-check`
