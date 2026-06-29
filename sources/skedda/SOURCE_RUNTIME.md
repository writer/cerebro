# Skedda

Generated Source Runtime SDK scaffold for `skedda`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/skedda`
- Health endpoint: `/source-runtimes/health?source_id=skedda`
- Source health receipt: `sources/skedda/source_health_receipt.json`
- EvidenceCAS reference kind: `skedda.evidence_cas_reference`

## Families

- `users`, emits `skedda.users`, reads `/v1/users`
- `groups`, emits `skedda.groups`, reads `/v1/groups`
- `workspaces`, emits `skedda.workspaces`, reads `/v1/workspaces`
- `documents`, emits `skedda.documents`, reads `/v1/documents`
- `audit_events`, emits `skedda.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/skedda ./internal/sourceprojection -count=1`
- `make catalog-check`
