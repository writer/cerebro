# Apigee

Provider-verified Source Runtime SDK for `apigee`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token` carrying a Google OAuth2 access token
- Base URL: `https://apigee.googleapis.com`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/apigee`
- Health endpoint: `/source-runtimes/health?source_id=apigee`
- Source health receipt: `sources/apigee/source_health_receipt.json`
- EvidenceCAS reference kind: `apigee.evidence_cas_reference`

## Families

- `organizations`, emits `apigee.organizations`, reads `GET /v1/organizations`
- `api_proxies`, emits `apigee.api_proxies`, reads `GET /v1/{parent=organizations/*}/apis`
- `deployments`, emits `apigee.deployments`, reads `GET /v1/{parent=organizations/*}/deployments`
- `developers`, emits `apigee.developers`, reads `GET /v1/{parent=organizations/*}/developers`
- `apps`, emits `apigee.apps`, reads `GET /v1/{parent=organizations/*}/apps`

## Tests

- `go test ./sources/apigee ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/apigee/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
