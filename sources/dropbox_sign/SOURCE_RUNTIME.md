# Dropbox Sign

Generated Source Runtime SDK scaffold for `dropbox_sign`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/dropbox_sign`
- Health endpoint: `/source-runtimes/health?source_id=dropbox_sign`
- Source health receipt: `sources/dropbox_sign/source_health_receipt.json`
- EvidenceCAS reference kind: `dropbox_sign.evidence_cas_reference`

## Families

- `users`, emits `dropbox_sign.users`, reads `/v1/users`
- `groups`, emits `dropbox_sign.groups`, reads `/v1/groups`
- `workspaces`, emits `dropbox_sign.workspaces`, reads `/v1/workspaces`
- `documents`, emits `dropbox_sign.documents`, reads `/v1/documents`
- `audit_events`, emits `dropbox_sign.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/dropbox_sign ./internal/sourceprojection -count=1`
- `make catalog-check`
