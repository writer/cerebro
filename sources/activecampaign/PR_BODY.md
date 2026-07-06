## Summary

- Adds the `activecampaign` Source Runtime SDK scaffold.
- Promotes the runtime to provider-verified ActiveCampaign v3 API paths for users, accounts, contacts, campaigns, and automations.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `api_key` (`Api-Token` header)
- Health endpoint: `/source-runtimes/health?source_id=activecampaign`
- Provider API proof: `verified` / score `100`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/activecampaign ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/activecampaign/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
