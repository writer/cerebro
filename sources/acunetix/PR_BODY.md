## Summary

- Promotes the `acunetix` Source Runtime SDK package to provider-verified API proof.
- Reshapes generated placeholder families to documented Acunetix API resources: targets, scans, vulnerabilities, scanning profiles, and reports.
- Syncs runtime paths, connector catalog metadata, graph projectors, fixtures, and source-health metadata to the documented API.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `X-Auth` API key header
- Health endpoint: `/source-runtimes/health?source_id=acunetix`
- Freshness: `24h0m0s`
- Provider API proof score: 100
- Runtime depth: reference runtime

## Tests

- `go test ./sources/acunetix ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/acunetix/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
