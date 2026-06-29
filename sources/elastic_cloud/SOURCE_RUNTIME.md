# Elastic Cloud

Generated Source Runtime SDK scaffold for `elastic_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/elastic_cloud`
- Health endpoint: `/source-runtimes/health?source_id=elastic_cloud`
- Source health receipt: `sources/elastic_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `elastic_cloud.evidence_cas_reference`

## Families

- `alerts`, emits `elastic_cloud.alerts`, reads `/v1/alerts`
- `incidents`, emits `elastic_cloud.incidents`, reads `/v1/incidents`
- `monitors`, emits `elastic_cloud.monitors`, reads `/v1/monitors`
- `dashboards`, emits `elastic_cloud.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `elastic_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/elastic_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
