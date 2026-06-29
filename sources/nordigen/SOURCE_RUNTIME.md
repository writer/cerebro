# Nordigen

Generated Source Runtime SDK scaffold for `nordigen`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/nordigen`
- Health endpoint: `/source-runtimes/health?source_id=nordigen`
- Source health receipt: `sources/nordigen/source_health_receipt.json`
- EvidenceCAS reference kind: `nordigen.evidence_cas_reference`

## Families

- `account`, emits `nordigen.account`, reads `/api/v2/payments/account/`
- `creditor`, emits `nordigen.creditor`, reads `/api/v2/payments/creditors/`
- `enduser`, emits `nordigen.enduser`, reads `/api/v2/agreements/enduser/`
- `institution`, emits `nordigen.institution`, reads `/api/v2/institutions/`

## Tests

- `go test ./sources/nordigen ./internal/sourceprojection -count=1`
- `make catalog-check`
