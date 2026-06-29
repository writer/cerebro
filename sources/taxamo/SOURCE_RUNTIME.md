# Taxamo

Generated Source Runtime SDK scaffold for `taxamo`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/taxamo`
- Health endpoint: `/source-runtimes/health?source_id=taxamo`
- Source health receipt: `sources/taxamo/source_health_receipt.json`
- EvidenceCAS reference kind: `taxamo.evidence_cas_reference`

## Families

- `payment`, emits `taxamo.payment`, reads `/api/v1/transactions/${config.key}/payments`
- `refund`, emits `taxamo.refund`, reads `/api/v1/transactions/${config.key}/refunds`
- `transaction`, emits `taxamo.transaction`, reads `/api/v1/transactions`
- `vy`, emits `taxamo.vy`, reads `/api/v1/reports/eu/vies`

## Tests

- `go test ./sources/taxamo ./internal/sourceprojection -count=1`
- `make catalog-check`
