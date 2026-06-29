# Evernote Teams

Generated Source Runtime SDK scaffold for `evernote_teams`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/evernote_teams`
- Health endpoint: `/source-runtimes/health?source_id=evernote_teams`
- Source health receipt: `sources/evernote_teams/source_health_receipt.json`
- EvidenceCAS reference kind: `evernote_teams.evidence_cas_reference`

## Families

- `users`, emits `evernote_teams.users`, reads `/v1/users`
- `groups`, emits `evernote_teams.groups`, reads `/v1/groups`
- `workspaces`, emits `evernote_teams.workspaces`, reads `/v1/workspaces`
- `documents`, emits `evernote_teams.documents`, reads `/v1/documents`
- `audit_events`, emits `evernote_teams.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/evernote_teams ./internal/sourceprojection -count=1`
- `make catalog-check`
