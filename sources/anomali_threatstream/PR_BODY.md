## Summary

- Records an evidenced provider API disproof for `anomali_threatstream`.
- Confirms the generated `/v1/*` runtime paths are not present in public Anomali ThreatStream API documentation or specifications.

## Disproof result

- Outcome: provider API proof invalidated.
- Evidence: provider-owned public pages confirm ThreatStream exposes APIs and SDKs, while the public SDK and third-party integration references corroborate the REST API V2 `intelligence` resource rather than the generated assets, findings, vulnerabilities, policies, or audit events paths.
- Next step: rewrite this source from a provider-published endpoint reference or machine-readable API spec before promotion.

## Tests

- `go test ./sources/anomali_threatstream ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/anomali_threatstream/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
