# JFrog Artifactory/Xray

Generated Source Runtime SDK scaffold for `jfrog_artifactory_xray`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/jfrog_artifactory_xray`
- Health endpoint: `/source-runtimes/health?source_id=jfrog_artifactory_xray`
- Source health receipt: `sources/jfrog_artifactory_xray/source_health_receipt.json`
- EvidenceCAS reference kind: `jfrog_artifactory_xray.evidence_cas_reference`

## Families

- `assets`, emits `jfrog_artifactory_xray.assets`, reads `/v1/assets`
- `findings`, emits `jfrog_artifactory_xray.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `jfrog_artifactory_xray.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/jfrog_artifactory_xray ./internal/sourceprojection -count=1`
- `make catalog-check`
