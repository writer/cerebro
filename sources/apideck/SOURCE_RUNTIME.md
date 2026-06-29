# Apideck

Generated Source Runtime SDK scaffold for `apideck`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/apideck`
- Health endpoint: `/source-runtimes/health?source_id=apideck`
- Source health receipt: `sources/apideck/source_health_receipt.json`
- EvidenceCAS reference kind: `apideck.evidence_cas_reference`

## Families

- `ledger_account`, emits `apideck.ledger_account`, reads `/accounting/ledger-accounts`
- `bill`, emits `apideck.bill`, reads `/accounting/bills`
- `credit_note`, emits `apideck.credit_note`, reads `/accounting/credit-notes`
- `customer`, emits `apideck.customer`, reads `/accounting/customers`

## Tests

- `go test ./sources/apideck ./internal/sourceprojection -count=1`
- `make catalog-check`
