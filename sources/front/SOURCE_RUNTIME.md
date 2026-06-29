# Front

Generated Source Runtime SDK scaffold for `front`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/front`
- Health endpoint: `/source-runtimes/health?source_id=front`
- Source health receipt: `sources/front/source_health_receipt.json`
- EvidenceCAS reference kind: `front.evidence_cas_reference`

## Families

- `users`, emits `front.users`, reads `/v1/users`
- `groups`, emits `front.groups`, reads `/v1/groups`
- `workspaces`, emits `front.workspaces`, reads `/v1/workspaces`
- `documents`, emits `front.documents`, reads `/v1/documents`
- `audit_events`, emits `front.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/front ./internal/sourceprojection -count=1`
- `make catalog-check`
