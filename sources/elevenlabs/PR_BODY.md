## Summary

- Updates the `elevenlabs` Source Runtime SDK with documented model, voice, service-account, webhook, and auth-connection APIs.
- Includes runtime adapter mappings, health checks, provider-shaped fixtures, tests, and a source-health receipt.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Health endpoint: `/source-runtimes/health?source_id=elevenlabs`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/elevenlabs -count=1`
