## Summary

- Records an evidenced provider API disproof for `agiloft`.
- Confirms Agiloft documents KB-specific `/ewws` REST operations and per-KB OpenAPI output, not stable `/v1` resource paths for the generated runtime families.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=agiloft`
- Freshness: `24h0m0s`

## Provider API proof

- Outcome: invalidated
- Reason: generated runtime paths are not present in the provider reference
- Affected families: `accounts`, `audit_events`, `policies`, `records`, `users`

## Tests

- `go test ./sources/agiloft ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/agiloft/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
