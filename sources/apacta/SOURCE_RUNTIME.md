# Apacta

Provider-verified Source Runtime SDK mapping for `apacta` using the documented Apacta Partner API.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: `Authorization: Bearer <token>` header
- Base URL: `https://app.apacta.com/api/v1`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/apacta`
- Health endpoint: `/source-runtimes/health?source_id=apacta`
- Source health receipt: `sources/apacta/source_health_receipt.json`
- EvidenceCAS reference kind: `apacta.evidence_cas_reference`

## Families

- `activity`, emits `apacta.activity`, reads `GET /activities`
- `city`, emits `apacta.city`, reads `GET /cities`
- `contact_person`, emits `apacta.contact_person`, reads `GET /contacts/{contact_id}/contact_persons`
- `projects_user`, emits `apacta.projects_user`, reads `GET /projects/{project_id}/users`
- `user`, emits `apacta.user`, reads `GET /users`

The generated families without stable Partner API endpoints were removed rather than mapped to unsupported paths.

## Tests

- `go test ./sources/apacta ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/apacta/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
