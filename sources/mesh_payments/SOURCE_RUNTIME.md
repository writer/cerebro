# Mesh Payments

Generated Source Runtime SDK scaffold for `mesh_payments`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mesh_payments`
- Health endpoint: `/source-runtimes/health?source_id=mesh_payments`
- Source health receipt: `sources/mesh_payments/source_health_receipt.json`
- EvidenceCAS reference kind: `mesh_payments.evidence_cas_reference`

## Families

- `users`, emits `mesh_payments.users`, reads `/v1/users`
- `accounts`, emits `mesh_payments.accounts`, reads `/v1/accounts`
- `records`, emits `mesh_payments.records`, reads `/v1/records`
- `policies`, emits `mesh_payments.policies`, reads `/v1/policies`
- `audit_events`, emits `mesh_payments.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/mesh_payments ./internal/sourceprojection -count=1`
- `make catalog-check`
