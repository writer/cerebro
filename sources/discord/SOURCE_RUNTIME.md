# Discord

Generated Source Runtime SDK scaffold for `discord`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/discord`
- Health endpoint: `/source-runtimes/health?source_id=discord`
- Source health receipt: `sources/discord/source_health_receipt.json`
- EvidenceCAS reference kind: `discord.evidence_cas_reference`

## Families

- `audit_log`, emits `discord.audit_log`, reads `/guilds/${config.guild_id}/audit-logs`
- `member`, emits `discord.member`, reads `/guilds/${config.guild_id}/members`
- `role`, emits `discord.role`, reads `/guilds/${config.guild_id}/roles`
- `permission`, emits `discord.permission`, reads `/applications/${config.application_id}/guilds/${config.guild_id}/commands/permissions`

## Tests

- `go test ./sources/discord ./internal/sourceprojection -count=1`
- `make catalog-check`
