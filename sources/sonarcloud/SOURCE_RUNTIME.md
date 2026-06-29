# SonarCloud

Generated Source Runtime SDK scaffold for `sonarcloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sonarcloud`
- Health endpoint: `/source-runtimes/health?source_id=sonarcloud`
- Source health receipt: `sources/sonarcloud/source_health_receipt.json`
- EvidenceCAS reference kind: `sonarcloud.evidence_cas_reference`

## Families

- `assets`, emits `sonarcloud.assets`, reads `/v1/assets`
- `findings`, emits `sonarcloud.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `sonarcloud.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/sonarcloud ./internal/sourceprojection -count=1`
- `make catalog-check`
