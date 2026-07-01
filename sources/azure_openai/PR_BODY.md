## Summary

- Updates the `azure_openai` Source Runtime SDK with Azure AI Services management APIs for deployments, models, RAI policies, RAI blocklists, and private endpoint connections.
- Includes runtime adapter mappings, health checks, provider-shaped fixtures, tests, and a source-health receipt.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=azure_openai`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/azure_openai -count=1`
