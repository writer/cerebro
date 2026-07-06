## Summary

- Records an evidenced provider API disproof for the generated `anomalo` source.
- Leaves the generated runtime scaffold unchanged because the public evidence does not ground the generated `/v1` family paths.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=anomalo`
- Freshness: `24h0m0s`

## Provider API proof outcome

- Outcome: disproven for promotion, `provider_api_disproof.status=invalidated`
- Reason: no provider-owned machine-readable specification or API reference was found for the generated runtime paths.
- Evidence reviewed: Anomalo API profile, Anomalo API-key setup guidance via Atlan, Anomalo's PyPI client package, and the public Go client endpoint list.

## Tests

- `go test ./sources/anomalo ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/anomalo/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
