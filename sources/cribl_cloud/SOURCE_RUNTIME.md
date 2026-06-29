# Cribl Cloud

Generated Source Runtime SDK scaffold for `cribl_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cribl_cloud`
- Health endpoint: `/source-runtimes/health?source_id=cribl_cloud`
- Source health receipt: `sources/cribl_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `cribl_cloud.evidence_cas_reference`

## Families

- `alerts`, emits `cribl_cloud.alerts`, reads `/v1/alerts`
- `incidents`, emits `cribl_cloud.incidents`, reads `/v1/incidents`
- `monitors`, emits `cribl_cloud.monitors`, reads `/v1/monitors`
- `dashboards`, emits `cribl_cloud.dashboards`, reads `/v1/dashboards`
- `audit_events`, emits `cribl_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cribl_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
