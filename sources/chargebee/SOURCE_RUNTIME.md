# Chargebee

Generated Source Runtime SDK scaffold for `chargebee`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/chargebee`
- Health endpoint: `/source-runtimes/health?source_id=chargebee`
- Source health receipt: `sources/chargebee/source_health_receipt.json`
- EvidenceCAS reference kind: `chargebee.evidence_cas_reference`

## Families

- `subscriptions`, emits `chargebee.subscriptions`, reads `/subscriptions`
- `customers`, emits `chargebee.customers`, reads `/customers`
- `audit_events`, emits `chargebee.audit_events`, reads `/events`

## Tests

- `go test ./sources/chargebee ./internal/sourceprojection -count=1`
- `make catalog-check`
