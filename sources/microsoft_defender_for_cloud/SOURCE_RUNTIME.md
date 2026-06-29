# Microsoft Defender for Cloud

Generated Source Runtime SDK scaffold for `microsoft_defender_for_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/microsoft_defender_for_cloud`
- Health endpoint: `/source-runtimes/health?source_id=microsoft_defender_for_cloud`
- Source health receipt: `sources/microsoft_defender_for_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `microsoft_defender_for_cloud.evidence_cas_reference`

## Families

- `assets`, emits `microsoft_defender_for_cloud.assets`, reads `/v1/assets`
- `findings`, emits `microsoft_defender_for_cloud.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `microsoft_defender_for_cloud.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/microsoft_defender_for_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
