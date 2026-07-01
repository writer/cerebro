## Summary

- Updates the `google_gemini` Source Runtime SDK with Gemini REST APIs for models, tuned models, files, cached contents, and batch jobs.
- Includes runtime adapter mappings, health checks, provider-shaped fixtures, tests, and a source-health receipt.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Health endpoint: `/source-runtimes/health?source_id=google_gemini`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/google_gemini -count=1`
