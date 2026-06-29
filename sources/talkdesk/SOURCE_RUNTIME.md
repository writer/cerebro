# Talkdesk

Generated Source Runtime SDK scaffold for `talkdesk`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/talkdesk`
- Health endpoint: `/source-runtimes/health?source_id=talkdesk`
- Source health receipt: `sources/talkdesk/source_health_receipt.json`
- EvidenceCAS reference kind: `talkdesk.evidence_cas_reference`

## Families

- `users`, emits `talkdesk.users`, reads `/v1/users`
- `groups`, emits `talkdesk.groups`, reads `/v1/groups`
- `workspaces`, emits `talkdesk.workspaces`, reads `/v1/workspaces`
- `documents`, emits `talkdesk.documents`, reads `/v1/documents`
- `audit_events`, emits `talkdesk.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/talkdesk ./internal/sourceprojection -count=1`
- `make catalog-check`
