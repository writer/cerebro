# Acunetix

Provider-verified Source Runtime SDK package for `acunetix`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `X-Auth` API key header
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/acunetix`
- Health endpoint: `/source-runtimes/health?source_id=acunetix`
- Source health receipt: `sources/acunetix/source_health_receipt.json`
- EvidenceCAS reference kind: `acunetix.evidence_cas_reference`

## Families

- `targets`, emits `acunetix.targets`, reads `GET /targets`
- `scans`, emits `acunetix.scans`, reads `GET /scans`
- `vulnerabilities`, emits `acunetix.vulnerabilities`, reads `GET /vulnerabilities`
- `scanning_profiles`, emits `acunetix.scanning_profiles`, reads `GET /scanning_profiles`
- `reports`, emits `acunetix.reports`, reads `GET /reports`

## Tests

- `go test ./sources/acunetix ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/acunetix/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
