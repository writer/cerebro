# BambooHR

Generated Source Runtime SDK scaffold for `bamboohr`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bamboohr`
- Health endpoint: `/source-runtimes/health?source_id=bamboohr`
- Source health receipt: `sources/bamboohr/source_health_receipt.json`
- EvidenceCAS reference kind: `bamboohr.evidence_cas_reference`

## Families

- `users`, emits `bamboohr.users`, reads `/v1/workers`
- `groups`, emits `bamboohr.groups`, reads `/v1/organizations`
- `audit_events`, emits `bamboohr.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/bamboohr ./internal/sourceprojection -count=1`
- `make catalog-check`
