# CockroachDB Cloud

Generated Source Runtime SDK scaffold for `cockroachdb_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cockroachdb_cloud`
- Health endpoint: `/source-runtimes/health?source_id=cockroachdb_cloud`
- Source health receipt: `sources/cockroachdb_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `cockroachdb_cloud.evidence_cas_reference`

## Families

- `assets`, emits `cockroachdb_cloud.assets`, reads `/v1/assets`
- `audit_events`, emits `cockroachdb_cloud.audit_events`, reads `/v1/audit/events`
- `vulnerabilities`, emits `cockroachdb_cloud.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/cockroachdb_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
