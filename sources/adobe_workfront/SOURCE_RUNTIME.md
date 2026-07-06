# Adobe Workfront

Provider-verified Source Runtime SDK for `adobe_workfront`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `apiKey` header
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/adobe_workfront`
- Health endpoint: `/source-runtimes/health?source_id=adobe_workfront`
- Source health receipt: `sources/adobe_workfront/source_health_receipt.json`
- EvidenceCAS reference kind: `adobe_workfront.evidence_cas_reference`

## Families

- `users`, emits `adobe_workfront.users`, reads `GET /user/search`
- `groups`, emits `adobe_workfront.groups`, reads `GET /group/search`
- `projects`, emits `adobe_workfront.projects`, reads `GET /proj/search`
- `documents`, emits `adobe_workfront.documents`, reads `GET /docu/search`
- `audit_events`, emits `adobe_workfront.audit_events`, reads `GET /jrnle/search` for JournalEntry change evidence

## Tests

- `go test ./sources/adobe_workfront ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/adobe_workfront/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
