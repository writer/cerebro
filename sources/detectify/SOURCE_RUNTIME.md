# Detectify

Generated Source Runtime SDK scaffold for `detectify`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/detectify`
- Health endpoint: `/source-runtimes/health?source_id=detectify`
- Source health receipt: `sources/detectify/source_health_receipt.json`
- EvidenceCAS reference kind: `detectify.evidence_cas_reference`

## Families

- `findings`, emits `detectify.findings`, reads `/v2/findings`
- `assets`, emits `detectify.assets`, reads `/v2/assets`
- `scan_profiles`, emits `detectify.scan_profiles`, reads `/v2/scanprofiles`

## Tests

- `go test ./sources/detectify ./internal/sourceprojection -count=1`
- `make catalog-check`
