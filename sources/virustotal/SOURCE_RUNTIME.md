# VirusTotal

Generated Source Runtime SDK scaffold for `virustotal`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/virustotal`
- Health endpoint: `/source-runtimes/health?source_id=virustotal`
- Source health receipt: `sources/virustotal/source_health_receipt.json`
- EvidenceCAS reference kind: `virustotal.evidence_cas_reference`

## Families

- `assets`, emits `virustotal.assets`, reads `/v1/assets`
- `findings`, emits `virustotal.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `virustotal.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/virustotal ./internal/sourceprojection -count=1`
- `make catalog-check`
