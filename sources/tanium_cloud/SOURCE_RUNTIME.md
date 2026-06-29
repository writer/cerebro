# Tanium Cloud

Generated Source Runtime SDK scaffold for `tanium_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/tanium_cloud`
- Health endpoint: `/source-runtimes/health?source_id=tanium_cloud`
- Source health receipt: `sources/tanium_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `tanium_cloud.evidence_cas_reference`

## Families

- `assets`, emits `tanium_cloud.assets`, reads `/v1/assets`
- `findings`, emits `tanium_cloud.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `tanium_cloud.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `tanium_cloud.policies`, reads `/v1/policies`
- `audit_events`, emits `tanium_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/tanium_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
