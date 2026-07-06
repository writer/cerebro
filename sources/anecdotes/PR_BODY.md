## Summary

- Records an evidenced provider API disproof for `anecdotes`.
- Confirms the generated `/v1/*` runtime paths are not present in public Anecdotes API documentation or specifications.

## Disproof result

- Outcome: provider API proof invalidated.
- Evidence: API Tracker lists no public Anecdotes API specifications, while provider-owned pages describe Data Engine, Data Studio, and MCP capabilities without endpoint-level API reference paths.
- Additional context: a public third-party user-management API guide also states that no official developer reference, OpenAPI spec, or sandbox environment has been published for Anecdotes user-management APIs, and distinguishes unrelated Anecdote AI public API docs from Anecdotes GRC.

## Tests

- `go test ./sources/anecdotes ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/anecdotes/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
