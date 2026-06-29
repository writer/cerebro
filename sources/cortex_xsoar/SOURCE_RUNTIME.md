# Cortex XSOAR

Generated Source Runtime SDK scaffold for `cortex_xsoar`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cortex_xsoar`
- Health endpoint: `/source-runtimes/health?source_id=cortex_xsoar`
- Source health receipt: `sources/cortex_xsoar/source_health_receipt.json`
- EvidenceCAS reference kind: `cortex_xsoar.evidence_cas_reference`

## Families

- `audit_events`, emits `cortex_xsoar.audit_events`, reads `/v1/events`
- `findings`, emits `cortex_xsoar.findings`, reads `/v1/cases`
- `assets`, emits `cortex_xsoar.assets`, reads `/v1/assets`

## Tests

- `go test ./sources/cortex_xsoar ./internal/sourceprojection -count=1`
- `make catalog-check`
