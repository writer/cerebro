# Magento

Generated Source Runtime SDK scaffold for `magento`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/magento`
- Health endpoint: `/source-runtimes/health?source_id=magento`
- Source health receipt: `sources/magento/source_health_receipt.json`
- EvidenceCAS reference kind: `magento.evidence_cas_reference`

## Families

- `attribute`, emits `magento.attribute`, reads `/V1/categories/attributes`
- `role`, emits `magento.role`, reads `/V1/company/role/`
- `search`, emits `magento.search`, reads `/V1/cmsPage/search`
- `coupons_search`, emits `magento.coupons_search`, reads `/V1/coupons/search`

## Tests

- `go test ./sources/magento ./internal/sourceprojection -count=1`
- `make catalog-check`
