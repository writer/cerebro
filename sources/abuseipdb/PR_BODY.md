## Summary

- Promotes the `abuseipdb` Source Runtime SDK to provider-verified API proof.
- Maps the runtime families to documented AbuseIPDB APIv2 endpoints for blacklist IP reputation entries and report history.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `Key: <api_key>` header
- Health endpoint: `/source-runtimes/health?source_id=abuseipdb`
- Freshness: `24h0m0s`
- Provider API proof score: `100`
- Provider API proof level: `verified`

## Tests

- `go test ./sources/abuseipdb ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/abuseipdb/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
