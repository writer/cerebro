# Braintree

Generated Source Runtime SDK scaffold for `braintree`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/braintree`
- Health endpoint: `/source-runtimes/health?source_id=braintree`
- Source health receipt: `sources/braintree/source_health_receipt.json`
- EvidenceCAS reference kind: `braintree.evidence_cas_reference`

## Families

- `transactions`, emits `braintree.transactions`, reads `/transactions`
- `customers`, emits `braintree.customers`, reads `/customers`
- `audit_events`, emits `braintree.audit_events`, reads `/audit-events`

## Tests

- `go test ./sources/braintree ./internal/sourceprojection -count=1`
- `make catalog-check`
