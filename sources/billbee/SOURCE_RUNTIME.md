# Billbee

Generated Source Runtime SDK scaffold for `billbee`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/billbee`
- Health endpoint: `/source-runtimes/health?source_id=billbee`
- Source health receipt: `sources/billbee/source_health_receipt.json`
- EvidenceCAS reference kind: `billbee.evidence_cas_reference`

## Families

- `webhook`, emits `billbee.webhook`, reads `/api/v1/webhooks`
- `cloudstorage`, emits `billbee.cloudstorage`, reads `/api/v1/cloudstorages`
- `custom_field`, emits `billbee.custom_field`, reads `/api/v1/products/custom-fields`
- `customer`, emits `billbee.customer`, reads `/api/v1/customers`
- `customer_addresses`, emits `billbee.customer_addresses`, reads `/api/v1/customer-addresses`
- `layout`, emits `billbee.layout`, reads `/api/v1/layouts`
- `order`, emits `billbee.order`, reads `/api/v1/orders`
- `product`, emits `billbee.product`, reads `/api/v1/products`
- `shipment`, emits `billbee.shipment`, reads `/api/v1/shipment/shipments`
- `stock`, emits `billbee.stock`, reads `/api/v1/products/stocks`
- `addresses`, emits `billbee.addresses`, reads `/api/v1/customers/${config.id}/addresses`
- `image`, emits `billbee.image`, reads `/api/v1/products/${config.productid}/images`

## Tests

- `go test ./sources/billbee ./internal/sourceprojection -count=1`
- `make catalog-check`
