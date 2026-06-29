# Slab

Generated Source Runtime SDK scaffold for `slab`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/slab`
- Health endpoint: `/source-runtimes/health?source_id=slab`
- Source health receipt: `sources/slab/source_health_receipt.json`
- EvidenceCAS reference kind: `slab.evidence_cas_reference`

## Families

- `users`, emits `slab.users`, reads `/v1/users`
- `groups`, emits `slab.groups`, reads `/v1/groups`
- `workspaces`, emits `slab.workspaces`, reads `/v1/workspaces`
- `documents`, emits `slab.documents`, reads `/v1/documents`
- `audit_events`, emits `slab.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/slab ./internal/sourceprojection -count=1`
- `make catalog-check`
