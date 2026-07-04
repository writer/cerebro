## Summary

- Deepens Google Drive runtime coverage for files, shared drives, and Drive changes.
- Adds provider-shaped fixtures, provider-unavailable coverage, and shared-drive deploy runtime coverage.
- Maps Drive file, shared-drive, and change fields into stable graph resource attributes.

## Runtime contract

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Runtime families: `files`, `shared_drives`
- Fixture families: `files`, `shared_drives`, `changes`

## Tests

- `go test ./sources/google_drive ./internal/connectorcatalog ./internal/sourceprojection -count=1`
- `make catalog-check`
