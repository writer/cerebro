# Databricks

Generated Source Runtime SDK scaffold for `databricks`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/databricks`
- Health endpoint: `/source-runtimes/health?source_id=databricks`
- Source health receipt: `sources/databricks/source_health_receipt.json`
- EvidenceCAS reference kind: `databricks.evidence_cas_reference`

## Families

- `assets`, emits `databricks.assets`, reads `/v1/assets`
- `model_serving_endpoints`, emits `databricks.model_serving_endpoints`, reads `/v1/model-serving/endpoints`
- `audit_events`, emits `databricks.audit_events`, reads `/v1/audit/events`
- `vulnerabilities`, emits `databricks.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/databricks ./internal/sourceprojection -count=1`
- `make catalog-check`
