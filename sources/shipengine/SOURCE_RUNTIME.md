# ShipEngine

Generated Source Runtime SDK scaffold for `shipengine`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/shipengine`
- Health endpoint: `/source-runtimes/health?source_id=shipengine`
- Source health receipt: `sources/shipengine/source_health_receipt.json`
- EvidenceCAS reference kind: `shipengine.evidence_cas_reference`

## Families

- `tracking`, emits `shipengine.tracking`, reads `/v1/tracking`
- `package`, emits `shipengine.package`, reads `/v1/packages`
- `track`, emits `shipengine.track`, reads `/v1/labels/${config.label_id}/track`
- `webhook`, emits `shipengine.webhook`, reads `/v1/environment/webhooks`

## Tests

- `go test ./sources/shipengine ./internal/sourceprojection -count=1`
- `make catalog-check`
