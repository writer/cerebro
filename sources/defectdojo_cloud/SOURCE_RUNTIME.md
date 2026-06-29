# Defectdojo Cloud

Generated Source Runtime SDK scaffold for `defectdojo_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/defectdojo_cloud`
- Health endpoint: `/source-runtimes/health?source_id=defectdojo_cloud`
- Source health receipt: `sources/defectdojo_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `defectdojo_cloud.evidence_cas_reference`

## Families

- `assets`, emits `defectdojo_cloud.assets`, reads `/v1/assets`
- `findings`, emits `defectdojo_cloud.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `defectdojo_cloud.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `defectdojo_cloud.policies`, reads `/v1/policies`
- `audit_events`, emits `defectdojo_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/defectdojo_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
