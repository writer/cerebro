# Ordway

Generated Source Runtime SDK scaffold for `ordway`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ordway`
- Health endpoint: `/source-runtimes/health?source_id=ordway`
- Source health receipt: `sources/ordway/source_health_receipt.json`
- EvidenceCAS reference kind: `ordway.evidence_cas_reference`

## Families

- `users`, emits `ordway.users`, reads `/v1/users`
- `accounts`, emits `ordway.accounts`, reads `/v1/accounts`
- `records`, emits `ordway.records`, reads `/v1/records`
- `policies`, emits `ordway.policies`, reads `/v1/policies`
- `audit_events`, emits `ordway.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/ordway ./internal/sourceprojection -count=1`
- `make catalog-check`
