# Jumpseller

Generated Source Runtime SDK scaffold for `jumpseller`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/jumpseller`
- Health endpoint: `/source-runtimes/health?source_id=jumpseller`
- Source health receipt: `sources/jumpseller/source_health_receipt.json`
- EvidenceCAS reference kind: `jumpseller.evidence_cas_reference`

## Families

- `hooks_json`, emits `jumpseller.hooks_json`, reads `/hooks.json`
- `checkout_custom_fields_json`, emits `jumpseller.checkout_custom_fields_json`, reads `/checkout_custom_fields.json`
- `countries_json`, emits `jumpseller.countries_json`, reads `/countries.json`
- `custom_fields_json`, emits `jumpseller.custom_fields_json`, reads `/custom_fields.json`
- `customer_categories_json`, emits `jumpseller.customer_categories_json`, reads `/customer_categories.json`
- `customers_json`, emits `jumpseller.customers_json`, reads `/customers.json`
- `fulfillments_json`, emits `jumpseller.fulfillments_json`, reads `/fulfillments.json`
- `jsapps_json`, emits `jumpseller.jsapps_json`, reads `/jsapps.json`
- `orders_json`, emits `jumpseller.orders_json`, reads `/orders.json`
- `pages_json`, emits `jumpseller.pages_json`, reads `/pages.json`
- `payment_methods_json`, emits `jumpseller.payment_methods_json`, reads `/payment_methods.json`
- `products_json`, emits `jumpseller.products_json`, reads `/products.json`

## Tests

- `go test ./sources/jumpseller ./internal/sourceprojection -count=1`
- `make catalog-check`
