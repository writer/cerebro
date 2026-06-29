# Whereby

Generated Source Runtime SDK scaffold for `whereby`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/whereby`
- Health endpoint: `/source-runtimes/health?source_id=whereby`
- Source health receipt: `sources/whereby/source_health_receipt.json`
- EvidenceCAS reference kind: `whereby.evidence_cas_reference`

## Families

- `users`, emits `whereby.users`, reads `/v1/users`
- `groups`, emits `whereby.groups`, reads `/v1/groups`
- `workspaces`, emits `whereby.workspaces`, reads `/v1/workspaces`
- `documents`, emits `whereby.documents`, reads `/v1/documents`
- `audit_events`, emits `whereby.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/whereby ./internal/sourceprojection -count=1`
- `make catalog-check`
