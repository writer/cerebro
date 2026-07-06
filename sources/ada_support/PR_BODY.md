## Summary

- Promotes the `ada_support` Source Runtime SDK to provider-verified API proof.
- Reshapes generated placeholder families to documented Ada API resources: end users, platform integrations, conversations, knowledge articles, and audit log events.
- Syncs runtime paths, catalog proof metadata, connector definition, fixtures, health receipt, and projection registrations.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Provider API proof score: 100
- Runtime depth: reference runtime

## Tests

- `go test ./sources/ada_support ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/ada_support/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
