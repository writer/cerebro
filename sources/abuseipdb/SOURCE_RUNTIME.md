# AbuseIPDB

Provider-verified Source Runtime SDK for `abuseipdb`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `Key: <api_key>` header
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/abuseipdb`
- Health endpoint: `/source-runtimes/health?source_id=abuseipdb`
- Source health receipt: `sources/abuseipdb/source_health_receipt.json`
- EvidenceCAS reference kind: `abuseipdb.evidence_cas_reference`

## Families

- `ip_addresses`, emits `abuseipdb.ip_addresses`, reads `GET /blacklist` for documented AbuseIPDB blacklist IP reputation entries.
- `reports`, emits `abuseipdb.reports`, reads `GET /reports` for report history for a configured `ip_address`.

## Tests

- `go test ./sources/abuseipdb ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/abuseipdb/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
