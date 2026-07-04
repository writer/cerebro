## Summary

- Promotes the `hashicorp_vault` Source Runtime contract to provider-verified API proof.
- Replaces generated placeholder paths with Vault identity entity, mounted secret engine, and audit device endpoints.
- Refreshes the runtime notes, catalog proof, built-in connector definition, and health receipt to match the implemented runtime.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `X-Vault-Token`
- Health endpoint: `/source-runtimes/health?source_id=hashicorp_vault`
- Families: `users`, `secrets`, `audit_events`

## Tests

- `go test ./sources/hashicorp_vault ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `make lint-sources catalog-check sourcegen-check check-structural check-structural-test check-arch`
- `make connector-catalog-review connector-api-discovery`
- `make docs-drift-check oss-audit`

## Review output

- `hashicorp_vault` runtime depth score: `100`
- `hashicorp_vault` fidelity score: `100`
- `hashicorp_vault` provider API proof score: `100`
