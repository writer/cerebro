# Zoom Phone

Generated Source Runtime SDK scaffold for `zoom_phone`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zoom_phone`
- Health endpoint: `/source-runtimes/health?source_id=zoom_phone`
- Source health receipt: `sources/zoom_phone/source_health_receipt.json`
- EvidenceCAS reference kind: `zoom_phone.evidence_cas_reference`

## Families

- `users`, emits `zoom_phone.users`, reads `/v1/users`
- `groups`, emits `zoom_phone.groups`, reads `/v1/groups`
- `workspaces`, emits `zoom_phone.workspaces`, reads `/v1/workspaces`
- `documents`, emits `zoom_phone.documents`, reads `/v1/documents`
- `audit_events`, emits `zoom_phone.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zoom_phone ./internal/sourceprojection -count=1`
- `make catalog-check`
