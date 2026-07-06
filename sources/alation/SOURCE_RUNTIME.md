# Alation

Provider-verified Source Runtime SDK mapping for `alation`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key` using the Alation `TOKEN` header
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/alation`
- Health endpoint: `/source-runtimes/health?source_id=alation`
- Source health receipt: `sources/alation/source_health_receipt.json`
- EvidenceCAS reference kind: `alation.evidence_cas_reference`

## Families

- `users`, emits `alation.users`, reads `GET /integration/v2/user/`
- `groups`, emits `alation.groups`, reads `GET /integration/v1/group/`
- `data_sources`, emits `alation.data_sources`, reads `GET /integration/v1/datasource/`
- `policies`, emits `alation.policies`, reads `GET /integration/v1/business_policies/`
- `terms`, emits `alation.terms`, reads `GET /integration/v2/term/`

All runtime families use documented Alation API endpoints with `limit` and `skip` pagination.

## Tests

- `go test ./sources/alation ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/alation/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
