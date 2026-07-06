# Apache Airflow

Provider-verified Source Runtime SDK adapter for `apache`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Auth mechanics: HTTP Basic `Authorization` header using an Airflow username and password
- Base URL: Apache Airflow stable REST API root, for example `https://airflow.example.com/api/v1`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/apache`
- Adapter health path: `GET /eventLogs`
- Health endpoint: `/source-runtimes/health?source_id=apache`
- Source health receipt: `sources/apache/source_health_receipt.json`
- EvidenceCAS reference kind: `apache.evidence_cas_reference`

## Families

- `eventlog`, emits `apache.eventlog`, reads `GET /eventLogs` for Airflow audit log entries.
- `role`, emits `apache.role`, reads `GET /roles` for Airflow FAB roles.
- `user`, emits `apache.user`, reads `GET /users` for Airflow FAB users.
- `permission`, emits `apache.permission`, reads `GET /permissions` for Airflow FAB actions.

## Tests

- `go test ./sources/apache ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/apache/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
