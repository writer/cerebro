# Apache Airflow

Generated Source Runtime SDK scaffold for `apache`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/apache`
- Health endpoint: `/source-runtimes/health?source_id=apache`
- Source health receipt: `sources/apache/source_health_receipt.json`
- EvidenceCAS reference kind: `apache.evidence_cas_reference`

## Families

- `eventlog`, emits `apache.eventlog`, reads `/eventLogs`
- `role`, emits `apache.role`, reads `/roles`
- `user`, emits `apache.user`, reads `/users`
- `permission`, emits `apache.permission`, reads `/permissions`

## Tests

- `go test ./sources/apache ./internal/sourceprojection -count=1`
- `make catalog-check`
