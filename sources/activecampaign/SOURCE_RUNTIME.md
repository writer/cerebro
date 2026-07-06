# ActiveCampaign

Provider-verified Source Runtime SDK scaffold for `activecampaign`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key` via the `Api-Token` header
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/activecampaign`
- Health endpoint: `/source-runtimes/health?source_id=activecampaign`
- Source health receipt: `sources/activecampaign/source_health_receipt.json`
- EvidenceCAS reference kind: `activecampaign.evidence_cas_reference`

## Provider API proof

- Status: `verified`
- Base URL: ActiveCampaign account API origin, for example `https://youraccountname.api-us1.com`
- Health check: `GET /api/3/users/me`
- References: ActiveCampaign v3 REST API reference and per-resource Markdown OpenAPI snippets.

## Families

- `users`, emits `activecampaign.users`, reads `GET /api/3/users`
- `accounts`, emits `activecampaign.accounts`, reads `GET /api/3/accounts`
- `contacts`, emits `activecampaign.contacts`, reads `GET /api/3/contacts`
- `campaigns`, emits `activecampaign.campaigns`, reads `GET /api/3/campaigns`
- `automations`, emits `activecampaign.automations`, reads `GET /api/3/automations`

## Tests

- `go test ./sources/activecampaign ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/activecampaign/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
