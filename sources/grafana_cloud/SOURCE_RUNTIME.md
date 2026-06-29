# Grafana Cloud

Generated Source Runtime SDK scaffold for `grafana_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/grafana_cloud`
- Health endpoint: `/source-runtimes/health?source_id=grafana_cloud`
- Source health receipt: `sources/grafana_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `grafana_cloud.evidence_cas_reference`

## Families

- `assets`, emits `grafana_cloud.assets`, reads `/v1/entities`
- `findings`, emits `grafana_cloud.findings`, reads `/v1/alerts`
- `audit_events`, emits `grafana_cloud.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/grafana_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
