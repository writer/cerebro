# Sumo Logic

Generated Source Runtime SDK scaffold for `sumo_logic`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sumo_logic`
- Health endpoint: `/source-runtimes/health?source_id=sumo_logic`
- Source health receipt: `sources/sumo_logic/source_health_receipt.json`
- EvidenceCAS reference kind: `sumo_logic.evidence_cas_reference`

## Families

- `audit_events`, emits `sumo_logic.audit_events`, reads `/v1/events`
- `findings`, emits `sumo_logic.findings`, reads `/v1/detections`
- `assets`, emits `sumo_logic.assets`, reads `/v1/assets`

## Tests

- `go test ./sources/sumo_logic ./internal/sourceprojection -count=1`
- `make catalog-check`
