## Summary

- Promotes the `apache` Source Runtime SDK adapter to provider-verified API proof for Apache Airflow.
- Maps event logs, roles, users, and permissions to documented Apache Airflow stable REST API endpoints and keeps the runtime adapter, catalog, connector definition, tests, deployment manifest, and health receipt in sync.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `basic`
- Auth mechanics: HTTP Basic username/password authorization header
- Base URL: Apache Airflow stable REST API root, for example `https://airflow.example.com/api/v1`
- Health endpoint: `/source-runtimes/health?source_id=apache`
- Freshness: `24h0m0s`
- Provider API proof score: `100`
- Provider API proof level: `verified`
- Runtime depth: `reference_runtime`

## Tests

- `go test ./sources/apache ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/apache/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
