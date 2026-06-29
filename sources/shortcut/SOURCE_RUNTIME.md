# Shortcut

Generated Source Runtime SDK scaffold for `shortcut`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/shortcut`
- Health endpoint: `/source-runtimes/health?source_id=shortcut`
- Source health receipt: `sources/shortcut/source_health_receipt.json`
- EvidenceCAS reference kind: `shortcut.evidence_cas_reference`

## Families

- `users`, emits `shortcut.users`, reads `/v1/users`
- `projects`, emits `shortcut.projects`, reads `/v1/projects`
- `repositories`, emits `shortcut.repositories`, reads `/v1/repositories`
- `deployments`, emits `shortcut.deployments`, reads `/v1/deployments`
- `audit_events`, emits `shortcut.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/shortcut ./internal/sourceprojection -count=1`
- `make catalog-check`
