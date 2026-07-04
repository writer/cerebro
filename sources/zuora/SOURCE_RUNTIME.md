# Zuora

Source Runtime adapter for Zuora billing, notification, product, and revenue configuration.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Base URL: `https://rest.zuora.com`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zuora`
- Health endpoint: `/source-runtimes/health?source_id=zuora`
- Source health receipt: `sources/zuora/source_health_receipt.json`
- EvidenceCAS reference kind: `zuora.evidence_cas_reference`

## Provider API status

- Status: invalidated for promotion.
- Reason: generated runtime paths not present in the provider Swagger.
- Affected families: `account`, `revenue_event`, `revenue_schedule`.
- The remaining nine runtime family paths are present in the provider Swagger and should be promoted after the generated families are rewritten or removed.

## Families

- `event_trigger`, emits `zuora.event_trigger`, reads `/events/event-triggers`
- `accounting_code`, emits `zuora.accounting_code`, reads `/v1/accounting-codes`
- `callout`, emits `zuora.callout`, reads `/v1/notification-history/callout`
- `hostedpage`, emits `zuora.hostedpage`, reads `/v1/hostedpages`
- `product`, emits `zuora.product`, reads `/v1/catalog/products`
- `accounting_period`, emits `zuora.accounting_period`, reads `/v1/accounting-periods`
- `email`, emits `zuora.email`, reads `/v1/notification-history/email`
- `email_template`, emits `zuora.email_template`, reads `/notifications/email-templates`
- `notification_definition`, emits `zuora.notification_definition`, reads `/notifications/notification-definitions`
- `revenue_event`, emits `zuora.revenue_event`, reads `/v1/revenue-items/revenue-events/${config.event_number}`
- `revenue_schedule`, emits `zuora.revenue_schedule`, reads `/v1/revenue-events/revenue-schedules/${config.rs_number}`
- `account`, emits `zuora.account`, reads `/v1/payment-methods/credit-cards/accounts/${config.account_key}`

## Tests

- `go test ./sources/zuora ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `make catalog-check`
- `make connector-catalog-review connector-api-discovery`
