# GoDaddy

Generated Source Runtime SDK scaffold for `godaddy`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/godaddy`
- Health endpoint: `/source-runtimes/health?source_id=godaddy`
- Source health receipt: `sources/godaddy/source_health_receipt.json`
- EvidenceCAS reference kind: `godaddy.evidence_cas_reference`

## Families

- `optin`, emits `godaddy.optin`, reads `/v2/customers/${config.customerid}/domains/notifications/optIn`
- `domain`, emits `godaddy.domain`, reads `/v1/domains`
- `maintenance`, emits `godaddy.maintenance`, reads `/v2/domains/maintenances`
- `tld`, emits `godaddy.tld`, reads `/v1/domains/tlds`

## Tests

- `go test ./sources/godaddy ./internal/sourceprojection -count=1`
- `make catalog-check`
