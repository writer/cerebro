# Qdrant Cloud

Generated Source Runtime SDK scaffold for `qdrant_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/qdrant_cloud`
- Health endpoint: `/source-runtimes/health?source_id=qdrant_cloud`
- Source health receipt: `sources/qdrant_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `qdrant_cloud.evidence_cas_reference`

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

- `go test ./sources/qdrant_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
