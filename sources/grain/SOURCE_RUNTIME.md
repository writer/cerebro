# Grain

Generated Source Runtime SDK scaffold for `grain`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/grain`
- Health endpoint: `/source-runtimes/health?source_id=grain`
- Source health receipt: `sources/grain/source_health_receipt.json`
- EvidenceCAS reference kind: `grain.evidence_cas_reference`

## Families

- `users`, emits `grain.users`, reads `/v1/users`
- `groups`, emits `grain.groups`, reads `/v1/groups`
- `workspaces`, emits `grain.workspaces`, reads `/v1/workspaces`
- `documents`, emits `grain.documents`, reads `/v1/documents`
- `audit_events`, emits `grain.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/grain ./internal/sourceprojection -count=1`
- `make catalog-check`
