# Webex

Generated Source Runtime SDK scaffold for `webex`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/webex`
- Health endpoint: `/source-runtimes/health?source_id=webex`
- Source health receipt: `sources/webex/source_health_receipt.json`
- EvidenceCAS reference kind: `webex.evidence_cas_reference`

## Families

- `users`, emits `webex.users`, reads `/v1/users`
- `groups`, emits `webex.groups`, reads `/v1/groups`
- `workspaces`, emits `webex.workspaces`, reads `/v1/workspaces`
- `documents`, emits `webex.documents`, reads `/v1/documents`
- `audit_events`, emits `webex.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/webex ./internal/sourceprojection -count=1`
- `make catalog-check`
