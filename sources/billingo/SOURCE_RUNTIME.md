# Billingo

Generated Source Runtime SDK scaffold for `billingo`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/billingo`
- Health endpoint: `/source-runtimes/health?source_id=billingo`
- Source health receipt: `sources/billingo/source_health_receipt.json`
- EvidenceCAS reference kind: `billingo.evidence_cas_reference`

## Families

- `bank_account`, emits `billingo.bank_account`, reads `/bank-accounts`
- `document`, emits `billingo.document`, reads `/documents`
- `document_block`, emits `billingo.document_block`, reads `/document-blocks`
- `partner`, emits `billingo.partner`, reads `/partners`

## Tests

- `go test ./sources/billingo ./internal/sourceprojection -count=1`
- `make catalog-check`
