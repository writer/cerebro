# Robin

Generated Source Runtime SDK scaffold for `robin`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/robin`
- Health endpoint: `/source-runtimes/health?source_id=robin`
- Source health receipt: `sources/robin/source_health_receipt.json`
- EvidenceCAS reference kind: `robin.evidence_cas_reference`

## Families

- `users`, emits `robin.users`, reads `/v1/users`
- `groups`, emits `robin.groups`, reads `/v1/groups`
- `workspaces`, emits `robin.workspaces`, reads `/v1/workspaces`
- `documents`, emits `robin.documents`, reads `/v1/documents`
- `audit_events`, emits `robin.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/robin ./internal/sourceprojection -count=1`
- `make catalog-check`
