# Sigma Computing

Generated Source Runtime SDK scaffold for `sigma_computing`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sigma_computing`
- Health endpoint: `/source-runtimes/health?source_id=sigma_computing`
- Source health receipt: `sources/sigma_computing/source_health_receipt.json`
- EvidenceCAS reference kind: `sigma_computing.evidence_cas_reference`

## Families

- `users`, emits `sigma_computing.users`, reads `/v1/users`
- `accounts`, emits `sigma_computing.accounts`, reads `/v1/accounts`
- `records`, emits `sigma_computing.records`, reads `/v1/records`
- `policies`, emits `sigma_computing.policies`, reads `/v1/policies`
- `audit_events`, emits `sigma_computing.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sigma_computing ./internal/sourceprojection -count=1`
- `make catalog-check`
