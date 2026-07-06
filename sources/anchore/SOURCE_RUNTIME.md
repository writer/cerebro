# Anchore

Provider-verified Source Runtime SDK adapter for `anchore`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Base URL: renders `https://${config.enterprise_url}/v2` when `base_url` is unset.
- Required config: `enterprise_url`, `app_id`, `version_id`, `username`, `password`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/anchore`
- Adapter health path: `GET /system`
- Health endpoint: `/source-runtimes/health?source_id=anchore`
- Source health receipt: `sources/anchore/source_health_receipt.json`
- EvidenceCAS reference kind: `anchore.evidence_cas_reference`

## Families

- `assets`, emits `anchore.assets`, reads `GET /apps/{app_id}/versions/{version_id}/assets` for application version assets.
- `findings`, emits `anchore.findings`, reads `GET /apps/{app_id}/versions/{version_id}/policy/findings/all` for policy findings.
- `vulnerabilities`, emits `anchore.vulnerabilities`, reads `GET /apps/{app_id}/versions/{version_id}/vulnerabilities` for vulnerability matches.

## Tests

- `go test ./sources/anchore ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/anchore/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
