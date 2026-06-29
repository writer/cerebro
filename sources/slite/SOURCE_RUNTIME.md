# Slite

Generated Source Runtime SDK scaffold for `slite`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/slite`
- Health endpoint: `/source-runtimes/health?source_id=slite`
- Source health receipt: `sources/slite/source_health_receipt.json`
- EvidenceCAS reference kind: `slite.evidence_cas_reference`

## Families

- `users`, emits `slite.users`, reads `/v1/users`
- `groups`, emits `slite.groups`, reads `/v1/groups`
- `workspaces`, emits `slite.workspaces`, reads `/v1/workspaces`
- `documents`, emits `slite.documents`, reads `/v1/documents`
- `audit_events`, emits `slite.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/slite ./internal/sourceprojection -count=1`
- `make catalog-check`
