# Qdrant Cloud

Source Runtime adapter for Qdrant Cloud account, cluster, backup, database API key, and IAM role inventory.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `Authorization: apikey <management key>`
- Base URL: `https://api.cloud.qdrant.io`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/qdrant_cloud`
- Health endpoint: `/source-runtimes/health?source_id=qdrant_cloud`
- Source health receipt: `sources/qdrant_cloud/source_health_receipt.json`
- Emits account, identity, cluster, database API key, backup, backup schedule, and role configuration evidence.

## Families

- `accounts`, emits `qdrant_cloud.accounts`, reads `/api/account/v1/accounts`
- `account_members`, emits `qdrant_cloud.account_members`, reads `/api/account/v1/accounts/${config.account_id}/members`
- `clusters`, emits `qdrant_cloud.clusters`, reads `/api/cluster/v1/accounts/${config.account_id}/clusters`
- `database_api_keys`, emits `qdrant_cloud.database_api_keys`, reads `/api/cluster/auth/v2/accounts/${config.account_id}/database-api-keys`
- `backups`, emits `qdrant_cloud.backups`, reads `/api/cluster/backup/v1/accounts/${config.account_id}/backups`
- `backup_restores`, emits `qdrant_cloud.backup_restores`, reads `/api/cluster/backup/v1/accounts/${config.account_id}/backup_restores`
- `backup_schedules`, emits `qdrant_cloud.backup_schedules`, reads `/api/cluster/backup/v1/accounts/${config.account_id}/backup_schedules`
- `roles`, emits `qdrant_cloud.roles`, reads `/api/iam/v1/accounts/${config.account_id}/roles`

## Tests

- `go test ./sources/qdrant_cloud ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `make lint-sources catalog-check sourcegen-check check-structural check-structural-test check-arch`
- `make connector-catalog-review connector-api-discovery`
