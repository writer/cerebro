# Panther

Generated Source Runtime SDK scaffold for `panther`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/panther`
- Health endpoint: `/source-runtimes/health?source_id=panther`
- Source health receipt: `sources/panther/source_health_receipt.json`
- EvidenceCAS reference kind: `panther.evidence_cas_reference`

## Families

- `audit_events`, emits `panther.audit_events`, reads `/v1/events`
- `findings`, emits `panther.findings`, reads `/v1/detections`
- `assets`, emits `panther.assets`, reads `/v1/assets`

## Tests

- `go test ./sources/panther ./internal/sourceprojection -count=1`
- `make catalog-check`
