## Summary

- Promotes the `anchore` Source Runtime SDK adapter to provider-verified API proof.
- Maps assets, policy findings, and vulnerabilities to documented Anchore Enterprise V2 API endpoints and keeps the runtime adapter, catalog, connector definition, tests, deployment manifest, and health receipt in sync.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `basic`
- Health endpoint: `/source-runtimes/health?source_id=anchore`
- Freshness: `24h0m0s`
- Provider API proof: `100` (`verified`)
- Runtime depth: `reference_runtime`

## Tests

- `go test ./sources/anchore ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/anchore/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
