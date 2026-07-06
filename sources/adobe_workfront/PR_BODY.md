## Summary

- Promotes the `adobe_workfront` Source Runtime SDK to provider-verified API proof.
- Maps users, groups, projects, documents, and journal-derived audit events to documented Adobe Workfront OpenAPI endpoints.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `apiKey` header
- Health endpoint: `/source-runtimes/health?source_id=adobe_workfront`
- Freshness: `24h0m0s`
- Provider API proof score: `100`
- Provider API proof level: `verified`

## Tests

- `go test ./sources/adobe_workfront ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/adobe_workfront/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
