# Dynamics 365 Sales

Generated Source Runtime SDK scaffold for `dynamics_365_sales`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/dynamics_365_sales`
- Health endpoint: `/source-runtimes/health?source_id=dynamics_365_sales`
- Source health receipt: `sources/dynamics_365_sales/source_health_receipt.json`
- EvidenceCAS reference kind: `dynamics_365_sales.evidence_cas_reference`

## Families

- `users`, emits `dynamics_365_sales.users`, reads `/v1/users`
- `accounts`, emits `dynamics_365_sales.accounts`, reads `/v1/accounts`
- `records`, emits `dynamics_365_sales.records`, reads `/v1/records`
- `policies`, emits `dynamics_365_sales.policies`, reads `/v1/policies`
- `audit_events`, emits `dynamics_365_sales.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/dynamics_365_sales ./internal/sourceprojection -count=1`
- `make catalog-check`
