# Fulfillment.com

Generated Source Runtime SDK scaffold for `fulfillment_com`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fulfillment_com`
- Health endpoint: `/source-runtimes/health?source_id=fulfillment_com`
- Source health receipt: `sources/fulfillment_com/source_health_receipt.json`
- EvidenceCAS reference kind: `fulfillment_com.evidence_cas_reference`

## Families

- `accounting`, emits `fulfillment_com.accounting`, reads `/accounting`
- `inventory`, emits `fulfillment_com.inventory`, reads `/inventory`
- `return`, emits `fulfillment_com.return`, reads `/returns`
- `track`, emits `fulfillment_com.track`, reads `/track`

## Tests

- `go test ./sources/fulfillment_com ./internal/sourceprojection -count=1`
- `make catalog-check`
