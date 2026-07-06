# Airbrake

Provider-verified Source Runtime SDK for `airbrake`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `key` query parameter using an Airbrake user key, project key, or user token
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/airbrake`
- Health endpoint: `/source-runtimes/health?source_id=airbrake`
- Source health receipt: `sources/airbrake/source_health_receipt.json`
- EvidenceCAS reference kind: `airbrake.evidence_cas_reference`

## Families

- `projects`, emits `airbrake.projects`, reads `GET /api/v4/projects`
- `groups`, emits `airbrake.groups`, reads `GET /api/v4/groups`
- `deploys`, emits `airbrake.deploys`, reads `GET /api/v4/projects/{project_id}/deploys`
- `source_maps`, emits `airbrake.source_maps`, reads `GET /api/v4/projects/{project_id}/sourcemaps`
- `project_activities`, emits `airbrake.project_activities`, reads `GET /api/v4/projects/{project_id}/activities`

## Tests

- `go test ./sources/airbrake ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/airbrake/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
