# XTRF Home Portal API

Generated Source Runtime SDK scaffold for `xtrf_eu`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/xtrf_eu`
- Health endpoint: `/source-runtimes/health?source_id=xtrf_eu`
- Source health receipt: `sources/xtrf_eu/source_health_receipt.json`
- EvidenceCAS reference kind: `xtrf_eu.evidence_cas_reference`

## Families

- `user`, emits `xtrf_eu.user`, reads `/users`
- `active`, emits `xtrf_eu.active`, reads `/dictionaries/active`
- `all`, emits `xtrf_eu.all`, reads `/dictionaries/all`
- `customer`, emits `xtrf_eu.customer`, reads `/customers`
- `id`, emits `xtrf_eu.id`, reads `/accounting/customers/invoices/ids`
- `invoices_id`, emits `xtrf_eu.invoices_id`, reads `/accounting/providers/invoices/ids`
- `customers_id`, emits `xtrf_eu.customers_id`, reads `/customers/ids`
- `persons_id`, emits `xtrf_eu.persons_id`, reads `/customers/persons/ids`
- `projects_id`, emits `xtrf_eu.projects_id`, reads `/projects/ids`
- `providers_id`, emits `xtrf_eu.providers_id`, reads `/providers/ids`
- `id_2`, emits `xtrf_eu.id_2`, reads `/providers/persons/ids`
- `quotes_id`, emits `xtrf_eu.quotes_id`, reads `/quotes/ids`

## Tests

- `go test ./sources/xtrf_eu ./internal/sourceprojection -count=1`
- `make catalog-check`
