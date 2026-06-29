# Trello

Generated Source Runtime SDK scaffold for `trello`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/trello`
- Health endpoint: `/source-runtimes/health?source_id=trello`
- Source health receipt: `sources/trello/source_health_receipt.json`
- EvidenceCAS reference kind: `trello.evidence_cas_reference`

## Families

- `users`, emits `trello.users`, reads `/v1/users`
- `groups`, emits `trello.groups`, reads `/v1/groups`
- `workspaces`, emits `trello.workspaces`, reads `/v1/workspaces`
- `documents`, emits `trello.documents`, reads `/v1/documents`
- `audit_events`, emits `trello.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/trello ./internal/sourceprojection -count=1`
- `make catalog-check`
