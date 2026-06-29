# Truora

Generated Source Runtime SDK scaffold for `truora`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/truora`
- Health endpoint: `/source-runtimes/health?source_id=truora`
- Source health receipt: `sources/truora/source_health_receipt.json`
- EvidenceCAS reference kind: `truora.evidence_cas_reference`

## Families

- `hook`, emits `truora.hook`, reads `/v1/hooks`
- `report`, emits `truora.report`, reads `/v1/reports`
- `check`, emits `truora.check`, reads `/v1/checks`
- `config`, emits `truora.config`, reads `/v1/config`

## Tests

- `go test ./sources/truora ./internal/sourceprojection -count=1`
- `make catalog-check`
