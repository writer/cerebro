# Carbon Black Cloud

Generated Source Runtime SDK scaffold for `carbon_black_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/carbon_black_cloud`
- Health endpoint: `/source-runtimes/health?source_id=carbon_black_cloud`
- Source health receipt: `sources/carbon_black_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `carbon_black_cloud.evidence_cas_reference`

## Families

- `assets`, emits `carbon_black_cloud.assets`, reads `/v1/assets`
- `findings`, emits `carbon_black_cloud.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `carbon_black_cloud.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `carbon_black_cloud.policies`, reads `/v1/policies`
- `audit_events`, emits `carbon_black_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/carbon_black_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
