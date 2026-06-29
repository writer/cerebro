# Discourse

Generated Source Runtime SDK scaffold for `discourse`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/discourse`
- Health endpoint: `/source-runtimes/health?source_id=discourse`
- Source health receipt: `sources/discourse/source_health_receipt.json`
- EvidenceCAS reference kind: `discourse.evidence_cas_reference`

## Families

- `groups_json`, emits `discourse.groups_json`, reads `/groups.json`
- `user_actions_json`, emits `discourse.user_actions_json`, reads `/user_actions.json`
- `notifications_json`, emits `discourse.notifications_json`, reads `/notifications.json`
- `backups_json`, emits `discourse.backups_json`, reads `/admin/backups.json`

## Tests

- `go test ./sources/discourse ./internal/sourceprojection -count=1`
- `make catalog-check`
