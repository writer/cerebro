# Copper CRM

Generated Source Runtime SDK scaffold for `copper_crm`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/copper_crm`
- Health endpoint: `/source-runtimes/health?source_id=copper_crm`
- Source health receipt: `sources/copper_crm/source_health_receipt.json`
- EvidenceCAS reference kind: `copper_crm.evidence_cas_reference`

## Families

- `users`, emits `copper_crm.users`, reads `/v1/users`
- `accounts`, emits `copper_crm.accounts`, reads `/v1/accounts`
- `records`, emits `copper_crm.records`, reads `/v1/records`
- `policies`, emits `copper_crm.policies`, reads `/v1/policies`
- `audit_events`, emits `copper_crm.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/copper_crm ./internal/sourceprojection -count=1`
- `make catalog-check`
