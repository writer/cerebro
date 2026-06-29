# Sinao

Generated Source Runtime SDK scaffold for `sinao`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sinao`
- Health endpoint: `/source-runtimes/health?source_id=sinao`
- Source health receipt: `sources/sinao/source_health_receipt.json`
- EvidenceCAS reference kind: `sinao.evidence_cas_reference`

## Families

- `product`, emits `sinao.product`, reads `/apps/${config.appid}/products`
- `account`, emits `sinao.account`, reads `/apps/${config.appid}/accounts/`
- `organization`, emits `sinao.organization`, reads `/apps/${config.appid}/organizations`
- `rule`, emits `sinao.rule`, reads `/apps/${config.appid}/rules/`
- `access`, emits `sinao.access`, reads `/apps/${config.appid}/access`
- `productcategory`, emits `sinao.productcategory`, reads `/apps/${config.appid}/productcategory`
- `productstock`, emits `sinao.productstock`, reads `/apps/${config.appid}/productstocks`
- `accountcategory`, emits `sinao.accountcategory`, reads `/apps/${config.appid}/accountcategories/`
- `accounting_entry`, emits `sinao.accounting_entry`, reads `/apps/${config.appid}/accounting_entries/`
- `person`, emits `sinao.person`, reads `/apps/${config.appid}/persons`
- `invite`, emits `sinao.invite`, reads `/apps/${config.appid}/access/invite`
- `apps_organization`, emits `sinao.apps_organization`, reads `/apps/${config.appid}/organization`

## Tests

- `go test ./sources/sinao ./internal/sourceprojection -count=1`
- `make catalog-check`
