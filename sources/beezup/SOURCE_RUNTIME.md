# BeezUP

Generated Source Runtime SDK scaffold for `beezup`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/beezup`
- Health endpoint: `/source-runtimes/health?source_id=beezup`
- Source health receipt: `sources/beezup/source_health_receipt.json`
- EvidenceCAS reference kind: `beezup.evidence_cas_reference`

## Families

- `channelcatalog`, emits `beezup.channelcatalog`, reads `/v2/user/marketplaces/channelcatalogs/`
- `offer`, emits `beezup.offer`, reads `/v2/user/customer/offers`
- `filter`, emits `beezup.filter`, reads `/v2/user/analytics/${config.storeid}/reports/filters`
- `alert`, emits `beezup.alert`, reads `/v2/user/customer/stores/${config.storeid}/alerts`
- `catalogcolumn`, emits `beezup.catalogcolumn`, reads `/v2/user/catalogs/${config.storeid}/catalogColumns`
- `category`, emits `beezup.category`, reads `/v2/user/catalogs/${config.storeid}/categories`
- `customcolumn`, emits `beezup.customcolumn`, reads `/v2/user/catalogs/${config.storeid}/customColumns`
- `random`, emits `beezup.random`, reads `/v2/user/catalogs/${config.storeid}/products/random`
- `rule`, emits `beezup.rule`, reads `/v2/user/analytics/${config.storeid}/rules`
- `beezupcolumn`, emits `beezup.beezupcolumn`, reads `/v2/user/catalogs/beezupColumns`
- `filteroperator`, emits `beezup.filteroperator`, reads `/v2/user/channelCatalogs/filterOperators`
- `autoimport`, emits `beezup.autoimport`, reads `/v2/user/catalogs/${config.storeid}/autoImport`

## Tests

- `go test ./sources/beezup ./internal/sourceprojection -count=1`
- `make catalog-check`
