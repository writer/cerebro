## Summary

- Records an evidenced provider API disproof for the generated `apiiro` source.
- Leaves the generated runtime scaffold unchanged because public evidence does not ground the generated `/v1` family paths.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=apiiro`
- Freshness: `24h0m0s`

## Provider API proof outcome

- Outcome: disproven for promotion, `provider_api_disproof.status=invalidated`
- Reason: no public provider-owned API reference or machine-readable specification was found for the generated runtime families.
- Evidence reviewed: Apiiro's sign-in-gated documentation host, Cortex's Apiiro integration guidance, Apiiro's public MCP server manifest, and Apiiro public product pages.

## Tests

- `go test ./sources/apiiro ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/apiiro/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
