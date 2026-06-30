## Summary

- Updates the `cohere` Source Runtime SDK with documented model, connector, dataset, and fine-tuned model APIs.
- Includes runtime adapter mappings, health checks, provider-shaped fixtures, tests, and a source-health receipt.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=cohere`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/cohere -count=1`
