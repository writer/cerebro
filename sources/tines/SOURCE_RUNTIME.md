# Tines

Generated Source Runtime SDK scaffold for `tines`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/tines`
- Health endpoint: `/source-runtimes/health?source_id=tines`
- Source health receipt: `sources/tines/source_health_receipt.json`
- EvidenceCAS reference kind: `tines.evidence_cas_reference`

## Families

- `audit_events`, emits `tines.audit_events`, reads `/v1/events`
- `findings`, emits `tines.findings`, reads `/v1/cases`
- `assets`, emits `tines.assets`, reads `/v1/assets`

## Tests

- `go test ./sources/tines ./internal/sourceprojection -count=1`
- `make catalog-check`
