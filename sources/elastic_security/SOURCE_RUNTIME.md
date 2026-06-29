# Elastic Security

Generated Source Runtime SDK scaffold for `elastic_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/elastic_security`
- Health endpoint: `/source-runtimes/health?source_id=elastic_security`
- Source health receipt: `sources/elastic_security/source_health_receipt.json`
- EvidenceCAS reference kind: `elastic_security.evidence_cas_reference`

## Families

- `audit_events`, emits `elastic_security.audit_events`, reads `/v1/events`
- `findings`, emits `elastic_security.findings`, reads `/v1/detections`
- `assets`, emits `elastic_security.assets`, reads `/v1/assets`

## Tests

- `go test ./sources/elastic_security ./internal/sourceprojection -count=1`
- `make catalog-check`
