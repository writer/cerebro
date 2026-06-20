# Akeyless

Generated Source Runtime SDK scaffold for `akeyless`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/akeyless`
- Health endpoint: `/source-runtimes/health?source_id=akeyless`
- Source health receipt: `sources/akeyless/source_health_receipt.json`
- EvidenceCAS reference kind: `akeyless.evidence_cas_reference`

## Families

- `items`, emits `akeyless.items`, reads `/v2/items`
- `auth_methods`, emits `akeyless.auth_methods`, reads `/v2/auth-methods`
- `roles`, emits `akeyless.roles`, reads `/v2/roles`
- `audit_events`, emits `akeyless.audit_events`, reads `/v2/audit`

## Tests

- `go test ./sources/akeyless ./internal/sourceprojection -count=1`
- `make catalog-check`
