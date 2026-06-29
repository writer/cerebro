# Google Play Console

Generated Source Runtime SDK scaffold for `google_play_console`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/google_play_console`
- Health endpoint: `/source-runtimes/health?source_id=google_play_console`
- Source health receipt: `sources/google_play_console/source_health_receipt.json`
- EvidenceCAS reference kind: `google_play_console.evidence_cas_reference`

## Families

- `users`, emits `google_play_console.users`, reads `/v1/users`
- `projects`, emits `google_play_console.projects`, reads `/v1/projects`
- `repositories`, emits `google_play_console.repositories`, reads `/v1/repositories`
- `deployments`, emits `google_play_console.deployments`, reads `/v1/deployments`
- `audit_events`, emits `google_play_console.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/google_play_console ./internal/sourceprojection -count=1`
- `make catalog-check`
