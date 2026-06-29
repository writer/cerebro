# Rebilly

Generated Source Runtime SDK scaffold for `rebilly`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/rebilly`
- Health endpoint: `/source-runtimes/health?source_id=rebilly`
- Source health receipt: `sources/rebilly/source_health_receipt.json`
- EvidenceCAS reference kind: `rebilly.evidence_cas_reference`

## Families

- `customer_timeline_custom_event`, emits `rebilly.customer_timeline_custom_event`, reads `/customer-timeline-custom-events`
- `authentication_token`, emits `rebilly.authentication_token`, reads `/authentication-tokens`
- `bank_account`, emits `rebilly.bank_account`, reads `/bank-accounts`
- `aml`, emits `rebilly.aml`, reads `/aml`

## Tests

- `go test ./sources/rebilly ./internal/sourceprojection -count=1`
- `make catalog-check`
