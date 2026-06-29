# Oyster HR

Generated Source Runtime SDK scaffold for `oyster_hr`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/oyster_hr`
- Health endpoint: `/source-runtimes/health?source_id=oyster_hr`
- Source health receipt: `sources/oyster_hr/source_health_receipt.json`
- EvidenceCAS reference kind: `oyster_hr.evidence_cas_reference`

## Families

- `users`, emits `oyster_hr.users`, reads `/v1/users`
- `accounts`, emits `oyster_hr.accounts`, reads `/v1/accounts`
- `records`, emits `oyster_hr.records`, reads `/v1/records`
- `policies`, emits `oyster_hr.policies`, reads `/v1/policies`
- `audit_events`, emits `oyster_hr.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/oyster_hr ./internal/sourceprojection -count=1`
- `make catalog-check`
