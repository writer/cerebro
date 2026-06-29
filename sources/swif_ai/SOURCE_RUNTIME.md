# Swif.ai

Generated Source Runtime SDK scaffold for `swif_ai`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/swif_ai`
- Health endpoint: `/source-runtimes/health?source_id=swif_ai`
- Source health receipt: `sources/swif_ai/source_health_receipt.json`
- EvidenceCAS reference kind: `swif_ai.evidence_cas_reference`

## Families

- `users`, emits `swif_ai.users`, reads `/v1/users`
- `devices`, emits `swif_ai.devices`, reads `/v1/devices`
- `device_compliance`, emits `swif_ai.device_compliance`, reads `/v1/device-compliance`

## Tests

- `go test ./sources/swif_ai ./internal/sourceprojection -count=1`
- `make catalog-check`
