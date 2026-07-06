# Airfocus

Provider-verified Source Runtime SDK for `airfocus`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: `Authorization: Bearer <personal access token>`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/airfocus`
- Health endpoint: `/source-runtimes/health?source_id=airfocus`
- Source health receipt: `sources/airfocus/source_health_receipt.json`
- EvidenceCAS reference kind: `airfocus.evidence_cas_reference`

## Families

- `users`, emits `airfocus.users`, reads `GET /api/team/users`
- `workspaces`, emits `airfocus.workspaces`, reads `POST /api/workspaces/search`
- `workspace_groups`, emits `airfocus.workspace_groups`, reads `POST /api/workspaces/groups/search`
- `link_types`, emits `airfocus.link_types`, reads `POST /api/link-types/search`
- `api_keys`, emits `airfocus.api_keys`, reads `GET /api/profile/api-keys`

## Tests

- `go test ./sources/airfocus ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/airfocus/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
