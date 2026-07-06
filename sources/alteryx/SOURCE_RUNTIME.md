# Alteryx

Provider-verified Source Runtime SDK contract for `alteryx`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: OAuth2 access token sent as `Authorization: Bearer <token>`
- Base URL: `${config.base_url}/webapi`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/alteryx`
- Health endpoint: `/source-runtimes/health?source_id=alteryx`
- Source health receipt: `sources/alteryx/source_health_receipt.json`
- EvidenceCAS reference kind: `alteryx.evidence_cas_reference`

## Families

- `users`, emits `alteryx.users`, reads `GET /v3/users`
- `usergroups`, emits `alteryx.usergroups`, reads `GET /v3/usergroups`
- `workflows`, emits `alteryx.workflows`, reads `GET /v3/workflows`
- `collections`, emits `alteryx.collections`, reads `GET /v3/collections`
- `audit_events`, emits `alteryx.audit_events`, reads `GET /admin/v1/auditlog`

## Tests

- `go test ./sources/alteryx ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/alteryx/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
