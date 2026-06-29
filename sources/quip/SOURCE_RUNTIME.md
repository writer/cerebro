# Quip

Generated Source Runtime SDK scaffold for `quip`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/quip`
- Health endpoint: `/source-runtimes/health?source_id=quip`
- Source health receipt: `sources/quip/source_health_receipt.json`
- EvidenceCAS reference kind: `quip.evidence_cas_reference`

## Families

- `users`, emits `quip.users`, reads `/v1/users`
- `groups`, emits `quip.groups`, reads `/v1/groups`
- `workspaces`, emits `quip.workspaces`, reads `/v1/workspaces`
- `documents`, emits `quip.documents`, reads `/v1/documents`
- `audit_events`, emits `quip.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/quip ./internal/sourceprojection -count=1`
- `make catalog-check`
