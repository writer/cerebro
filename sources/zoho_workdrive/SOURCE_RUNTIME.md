# Zoho Workdrive

Generated Source Runtime SDK scaffold for `zoho_workdrive`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zoho_workdrive`
- Health endpoint: `/source-runtimes/health?source_id=zoho_workdrive`
- Source health receipt: `sources/zoho_workdrive/source_health_receipt.json`
- EvidenceCAS reference kind: `zoho_workdrive.evidence_cas_reference`

## Families

- `users`, emits `zoho_workdrive.users`, reads `/v1/users`
- `groups`, emits `zoho_workdrive.groups`, reads `/v1/groups`
- `workspaces`, emits `zoho_workdrive.workspaces`, reads `/v1/workspaces`
- `documents`, emits `zoho_workdrive.documents`, reads `/v1/documents`
- `audit_events`, emits `zoho_workdrive.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zoho_workdrive ./internal/sourceprojection -count=1`
- `make catalog-check`
