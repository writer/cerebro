# Chili Piper

Generated Source Runtime SDK scaffold for `chili_piper`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/chili_piper`
- Health endpoint: `/source-runtimes/health?source_id=chili_piper`
- Source health receipt: `sources/chili_piper/source_health_receipt.json`
- EvidenceCAS reference kind: `chili_piper.evidence_cas_reference`

## Families

- `users`, emits `chili_piper.users`, reads `/v1/users`
- `groups`, emits `chili_piper.groups`, reads `/v1/groups`
- `workspaces`, emits `chili_piper.workspaces`, reads `/v1/workspaces`
- `documents`, emits `chili_piper.documents`, reads `/v1/documents`
- `audit_events`, emits `chili_piper.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/chili_piper ./internal/sourceprojection -count=1`
- `make catalog-check`
