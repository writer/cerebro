# HITRUST MyCSF

Generated Source Runtime SDK scaffold for `hitrust_mycsf`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hitrust_mycsf`
- Health endpoint: `/source-runtimes/health?source_id=hitrust_mycsf`
- Source health receipt: `sources/hitrust_mycsf/source_health_receipt.json`
- EvidenceCAS reference kind: `hitrust_mycsf.evidence_cas_reference`

## Families

- `assessments`, emits `hitrust_mycsf.assessments`, reads `/api/v1/assessments`
- `controls`, emits `hitrust_mycsf.controls`, reads `/api/v1/controls`
- `evidence`, emits `hitrust_mycsf.evidence`, reads `/api/v1/evidence`

## Tests

- `go test ./sources/hitrust_mycsf ./internal/sourceprojection -count=1`
- `make catalog-check`
