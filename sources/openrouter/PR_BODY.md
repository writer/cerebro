## Summary

- Updates the `openrouter` Source Runtime SDK with documented management endpoints for organization members, API keys, BYOK provider credentials, and endpoint activity.
- Includes runtime adapter mappings, health check coverage, provider-shaped fixtures, tests, and a source-health receipt.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Health endpoint: `/source-runtimes/health?source_id=openrouter`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/openrouter -count=1`
