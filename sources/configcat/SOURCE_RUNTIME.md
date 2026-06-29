# ConfigCat

Generated Source Runtime SDK scaffold for `configcat`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/configcat`
- Health endpoint: `/source-runtimes/health?source_id=configcat`
- Source health receipt: `sources/configcat/source_health_receipt.json`
- EvidenceCAS reference kind: `configcat.evidence_cas_reference`

## Families

- `auditlog`, emits `configcat.auditlog`, reads `/v1/organizations/${config.organizationid}/auditlogs`
- `organization`, emits `configcat.organization`, reads `/v1/organizations`
- `member`, emits `configcat.member`, reads `/v1/organizations/${config.organizationid}/members`
- `permission`, emits `configcat.permission`, reads `/v1/products/${config.productid}/permissions`

## Tests

- `go test ./sources/configcat ./internal/sourceprojection -count=1`
- `make catalog-check`
