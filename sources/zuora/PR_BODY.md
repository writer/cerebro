## Summary

- Promotes `zuora` runtime fixtures and replay tests to provider-shaped source fidelity.
- Covers every runtime family in source tests and deploy runtime configuration.
- Documents provider-specific coverage mappings and known gaps for unsupported sensitive fields.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=zuora`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/zuora -count=1`
- `make catalog-check sourcegen-check`
- `go run ./tools/sourcefidelity -json-out /tmp/zuora-fidelity.json`
