## Summary

- Records an evidenced provider API disproof for `airbase`.
- Confirms the generated `/v1/*` runtime paths are not present in public Airbase API documentation.

## Disproof result

- Outcome: provider API proof invalidated.
- Evidence: Airbase's public developer portal describes an invite-only Guided Procurement API and does not publish endpoint paths for the generated runtime families.
- Additional context: public provisioning documentation confirms tenant-specific SCIM user provisioning, but not the generated `/v1/users`, `/v1/accounts`, `/v1/records`, `/v1/policies`, or `/v1/audit_events` paths.

## Tests

- `go test ./sources/airbase ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/airbase/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
