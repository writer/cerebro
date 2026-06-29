# Helpscout

Generated Source Runtime SDK scaffold for `helpscout`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/helpscout`
- Health endpoint: `/source-runtimes/health?source_id=helpscout`
- Source health receipt: `sources/helpscout/source_health_receipt.json`
- EvidenceCAS reference kind: `helpscout.evidence_cas_reference`

## Families

- `users`, emits `helpscout.users`, reads `/v1/users`
- `groups`, emits `helpscout.groups`, reads `/v1/groups`
- `workspaces`, emits `helpscout.workspaces`, reads `/v1/workspaces`
- `documents`, emits `helpscout.documents`, reads `/v1/documents`
- `audit_events`, emits `helpscout.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/helpscout ./internal/sourceprojection -count=1`
- `make catalog-check`
