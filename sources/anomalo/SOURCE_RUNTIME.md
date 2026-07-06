# Anomalo

Provider-verified Source Runtime SDK scaffold for `anomalo`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Base URL: Anomalo tenant public API base, for example `https://<tenant>/api/public/v1`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/anomalo`
- Health endpoint: `/source-runtimes/health?source_id=anomalo`
- Source health receipt: `sources/anomalo/source_health_receipt.json`
- EvidenceCAS reference kind: `anomalo.evidence_cas_reference`

## Families

- `warehouses`, emits `anomalo.warehouses`, reads `GET /api/public/v1/list_warehouses`
- `tables`, emits `anomalo.tables`, reads `GET /api/public/v1/get_table_information`
- `checks`, emits `anomalo.checks`, reads `GET /api/public/v1/get_checks_for_table`
- `notification_channels`, emits `anomalo.notification_channels`, reads `GET /api/public/v1/list_notification_channels`
- `organizations`, emits `anomalo.organizations`, reads `GET /api/public/v1/organizations`

## Tests

- `go test ./sources/anomalo ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/anomalo/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
