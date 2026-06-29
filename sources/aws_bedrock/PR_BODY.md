## Summary

- Adds the `aws_bedrock` Source Runtime SDK scaffold.
- Includes runtime adapter, health check, EvidenceCAS reference events, graph projection scaffolds, tests, and a source-health receipt.

## Generated runtime contract

- Source type: `json_api`
- Auth model: `aws_sigv4`
- Health endpoint: `/source-runtimes/health?source_id=aws_bedrock`
- Freshness: `24h0m0s`

## Tests

- `go test ./sources/aws_bedrock ./internal/sourceprojection -count=1`
- `make catalog-check`
