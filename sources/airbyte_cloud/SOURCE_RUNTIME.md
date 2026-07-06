# Airbyte Cloud

Provider-verified Source Runtime SDK for `airbyte_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: `bearer_authorization_header`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/airbyte_cloud`
- Health endpoint: `/source-runtimes/health?source_id=airbyte_cloud`
- Source health receipt: `sources/airbyte_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `airbyte_cloud.evidence_cas_reference`

## Families

- `connections`, emits `airbyte_cloud.connections`, reads `GET /connections`
- `organizations`, emits `airbyte_cloud.organizations`, reads `GET /organizations`
- `permissions`, emits `airbyte_cloud.permissions`, reads `GET /permissions`
- `sources`, emits `airbyte_cloud.sources`, reads `GET /sources`
- `users`, emits `airbyte_cloud.users`, reads `GET /users` with `organizationId` when `organization_id` is configured

## Tests

- `go test ./sources/airbyte_cloud ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/airbyte_cloud/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
