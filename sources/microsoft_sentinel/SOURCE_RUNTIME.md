# Microsoft Sentinel

Generated Source Runtime SDK scaffold for `microsoft_sentinel`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/microsoft_sentinel`
- Health endpoint: `/source-runtimes/health?source_id=microsoft_sentinel`
- Source health receipt: `sources/microsoft_sentinel/source_health_receipt.json`
- EvidenceCAS reference kind: `microsoft_sentinel.evidence_cas_reference`

## Families

- `audit_events`, emits `microsoft_sentinel.audit_events`, reads `/v1/events`
- `findings`, emits `microsoft_sentinel.findings`, reads `/v1/detections`
- `assets`, emits `microsoft_sentinel.assets`, reads `/v1/assets`

## Tests

- `go test ./sources/microsoft_sentinel ./internal/sourceprojection -count=1`
- `make catalog-check`
