# Fathom Video

Generated Source Runtime SDK scaffold for `fathom_video`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fathom_video`
- Health endpoint: `/source-runtimes/health?source_id=fathom_video`
- Source health receipt: `sources/fathom_video/source_health_receipt.json`
- EvidenceCAS reference kind: `fathom_video.evidence_cas_reference`

## Families

- `users`, emits `fathom_video.users`, reads `/v1/users`
- `groups`, emits `fathom_video.groups`, reads `/v1/groups`
- `workspaces`, emits `fathom_video.workspaces`, reads `/v1/workspaces`
- `documents`, emits `fathom_video.documents`, reads `/v1/documents`
- `audit_events`, emits `fathom_video.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/fathom_video ./internal/sourceprojection -count=1`
- `make catalog-check`
