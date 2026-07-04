# BeezUP

Source Runtime adapter for BeezUP catalog, marketplace channel, customer alert, and auto-import records.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Auth header: `Ocp-Apim-Subscription-Key`
- Base URL: `https://api.beezup.com`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/beezup`
- Health endpoint: `/source-runtimes/health?source_id=beezup`
- Source health receipt: `sources/beezup/source_health_receipt.json`
- EvidenceCAS reference kind: `beezup.evidence_cas_reference`

## Provider API status

- Status: partial provider mapping with invalidated generated analytics paths.
- Verified families: `alert`, `autoimport`, `beezupcolumn`, `catalogcolumn`, `category`, `channelcatalog`, `customcolumn`, `filteroperator`, `offer`, `random`.
- Invalidated families: `filter`, `rule`.
- Reason: the provider-generated client exposes report filters and rules as link model targets, but not as generated API operation rows.

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
- `filteroperator`, emits `beezup.filteroperator`, reads `/v2/user/channelCatalogs/exclusionFilterOperators`
- `autoimport`, emits `beezup.autoimport`, reads `/v2/user/catalogs/${config.storeid}/autoImport`

## Tests

- `go test ./sources/beezup ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `make catalog-check`
- `make connector-catalog-review connector-api-discovery`
