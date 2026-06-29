# Planview Adaptivework

Generated Source Runtime SDK scaffold for `planview_adaptivework`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/planview_adaptivework`
- Health endpoint: `/source-runtimes/health?source_id=planview_adaptivework`
- Source health receipt: `sources/planview_adaptivework/source_health_receipt.json`
- EvidenceCAS reference kind: `planview_adaptivework.evidence_cas_reference`

## Families

- `users`, emits `planview_adaptivework.users`, reads `/v1/users`
- `groups`, emits `planview_adaptivework.groups`, reads `/v1/groups`
- `workspaces`, emits `planview_adaptivework.workspaces`, reads `/v1/workspaces`
- `documents`, emits `planview_adaptivework.documents`, reads `/v1/documents`
- `audit_events`, emits `planview_adaptivework.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/planview_adaptivework ./internal/sourceprojection -count=1`
- `make catalog-check`
