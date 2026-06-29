# Smartsuite

Generated Source Runtime SDK scaffold for `smartsuite`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/smartsuite`
- Health endpoint: `/source-runtimes/health?source_id=smartsuite`
- Source health receipt: `sources/smartsuite/source_health_receipt.json`
- EvidenceCAS reference kind: `smartsuite.evidence_cas_reference`

## Families

- `users`, emits `smartsuite.users`, reads `/v1/users`
- `accounts`, emits `smartsuite.accounts`, reads `/v1/accounts`
- `records`, emits `smartsuite.records`, reads `/v1/records`
- `policies`, emits `smartsuite.policies`, reads `/v1/policies`
- `audit_events`, emits `smartsuite.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/smartsuite ./internal/sourceprojection -count=1`
- `make catalog-check`
