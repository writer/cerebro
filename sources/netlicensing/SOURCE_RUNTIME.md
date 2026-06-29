# Labs64 NetLicensing

Generated Source Runtime SDK scaffold for `netlicensing`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/netlicensing`
- Health endpoint: `/source-runtimes/health?source_id=netlicensing`
- Source health receipt: `sources/netlicensing/source_health_receipt.json`
- EvidenceCAS reference kind: `netlicensing.evidence_cas_reference`

## Families

- `token`, emits `netlicensing.token`, reads `/token`
- `license`, emits `netlicensing.license`, reads `/license`
- `licensee`, emits `netlicensing.licensee`, reads `/licensee`
- `licensetemplate`, emits `netlicensing.licensetemplate`, reads `/licensetemplate`

## Tests

- `go test ./sources/netlicensing ./internal/sourceprojection -count=1`
- `make catalog-check`
