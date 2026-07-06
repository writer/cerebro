## Summary

- Promotes the `abnormal_security` Source Runtime SDK to provider-verified API proof.
- Maps runtime families to documented Abnormal Security Client API endpoints for resources, threats, cases, posture catalog entries, and audit logs.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: `Authorization: Bearer <token>` header
- Health endpoint: `/source-runtimes/health?source_id=abnormal_security`
- Freshness: `24h0m0s`
- Provider API proof score: `100`
- Provider API proof level: `verified`

## Tests

- `go test ./sources/abnormal_security ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/abnormal_security/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
