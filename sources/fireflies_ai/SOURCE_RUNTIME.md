# Fireflies.ai

Generated Source Runtime SDK scaffold for `fireflies_ai`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fireflies_ai`
- Health endpoint: `/source-runtimes/health?source_id=fireflies_ai`
- Source health receipt: `sources/fireflies_ai/source_health_receipt.json`
- EvidenceCAS reference kind: `fireflies_ai.evidence_cas_reference`

## Families

- `users`, emits `fireflies_ai.users`, reads `/v1/users`
- `groups`, emits `fireflies_ai.groups`, reads `/v1/groups`
- `workspaces`, emits `fireflies_ai.workspaces`, reads `/v1/workspaces`
- `documents`, emits `fireflies_ai.documents`, reads `/v1/documents`
- `audit_events`, emits `fireflies_ai.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/fireflies_ai ./internal/sourceprojection -count=1`
- `make catalog-check`
