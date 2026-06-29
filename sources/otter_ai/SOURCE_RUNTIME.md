# Otter.ai

Generated Source Runtime SDK scaffold for `otter_ai`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/otter_ai`
- Health endpoint: `/source-runtimes/health?source_id=otter_ai`
- Source health receipt: `sources/otter_ai/source_health_receipt.json`
- EvidenceCAS reference kind: `otter_ai.evidence_cas_reference`

## Families

- `users`, emits `otter_ai.users`, reads `/v1/users`
- `groups`, emits `otter_ai.groups`, reads `/v1/groups`
- `workspaces`, emits `otter_ai.workspaces`, reads `/v1/workspaces`
- `documents`, emits `otter_ai.documents`, reads `/v1/documents`
- `audit_events`, emits `otter_ai.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/otter_ai ./internal/sourceprojection -count=1`
- `make catalog-check`
