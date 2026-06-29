# Wrike

Generated Source Runtime SDK scaffold for `wrike`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/wrike`
- Health endpoint: `/source-runtimes/health?source_id=wrike`
- Source health receipt: `sources/wrike/source_health_receipt.json`
- EvidenceCAS reference kind: `wrike.evidence_cas_reference`

## Families

- `users`, emits `wrike.users`, reads `/v1/users`
- `groups`, emits `wrike.groups`, reads `/v1/groups`
- `workspaces`, emits `wrike.workspaces`, reads `/v1/workspaces`
- `documents`, emits `wrike.documents`, reads `/v1/documents`
- `audit_events`, emits `wrike.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/wrike ./internal/sourceprojection -count=1`
- `make catalog-check`
