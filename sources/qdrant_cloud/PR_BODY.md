## Summary

- Promotes the `qdrant_cloud` Source Runtime contract to provider-verified API proof.
- Maps the existing runtime families to Qdrant Cloud Account, Cluster, Database API Key, Backup, and IAM services.
- Refreshes runtime notes, catalog coverage notes, deploy manifest coverage, and the source-health receipt to match the implemented runtime.

## Runtime contract

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `Authorization: apikey <management key>`
- Health endpoint: `/source-runtimes/health?source_id=qdrant_cloud`
- Families: `accounts`, `account_members`, `clusters`, `database_api_keys`, `backups`, `backup_restores`, `backup_schedules`, `roles`
- Deploy manifest: one runtime entry per family, using `QDRANT_CLOUD_MANAGEMENT_KEY` as `api_key`

## Tests

- `go test ./sources/qdrant_cloud ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `make lint-sources catalog-check sourcegen-check check-structural check-structural-test check-arch`
- `make connector-catalog-review connector-api-discovery`

## Review output

- Runtime depth score: `100`
- Fidelity score: `100`
- Provider API proof score: `100`
