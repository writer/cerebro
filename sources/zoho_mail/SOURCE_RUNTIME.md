# Zoho Mail

Generated Source Runtime SDK scaffold for `zoho_mail`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zoho_mail`
- Health endpoint: `/source-runtimes/health?source_id=zoho_mail`
- Source health receipt: `sources/zoho_mail/source_health_receipt.json`
- EvidenceCAS reference kind: `zoho_mail.evidence_cas_reference`

## Families

- `users`, emits `zoho_mail.users`, reads `/v1/users`
- `groups`, emits `zoho_mail.groups`, reads `/v1/groups`
- `workspaces`, emits `zoho_mail.workspaces`, reads `/v1/workspaces`
- `documents`, emits `zoho_mail.documents`, reads `/v1/documents`
- `audit_events`, emits `zoho_mail.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zoho_mail ./internal/sourceprojection -count=1`
- `make catalog-check`
