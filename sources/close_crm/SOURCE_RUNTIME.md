# Close CRM

Generated Source Runtime SDK scaffold for `close_crm`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/close_crm`
- Health endpoint: `/source-runtimes/health?source_id=close_crm`
- Source health receipt: `sources/close_crm/source_health_receipt.json`
- EvidenceCAS reference kind: `close_crm.evidence_cas_reference`

## Families

- `users`, emits `close_crm.users`, reads `/v1/users`
- `accounts`, emits `close_crm.accounts`, reads `/v1/accounts`
- `records`, emits `close_crm.records`, reads `/v1/records`
- `policies`, emits `close_crm.policies`, reads `/v1/policies`
- `audit_events`, emits `close_crm.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/close_crm ./internal/sourceprojection -count=1`
- `make catalog-check`
