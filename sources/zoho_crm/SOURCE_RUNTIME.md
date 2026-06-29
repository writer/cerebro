# Zoho CRM

Generated Source Runtime SDK scaffold for `zoho_crm`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zoho_crm`
- Health endpoint: `/source-runtimes/health?source_id=zoho_crm`
- Source health receipt: `sources/zoho_crm/source_health_receipt.json`
- EvidenceCAS reference kind: `zoho_crm.evidence_cas_reference`

## Families

- `users`, emits `zoho_crm.users`, reads `/v1/users`
- `accounts`, emits `zoho_crm.accounts`, reads `/v1/accounts`
- `records`, emits `zoho_crm.records`, reads `/v1/records`
- `policies`, emits `zoho_crm.policies`, reads `/v1/policies`
- `audit_events`, emits `zoho_crm.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zoho_crm ./internal/sourceprojection -count=1`
- `make catalog-check`
