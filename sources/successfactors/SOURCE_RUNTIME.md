# Successfactors

Generated Source Runtime SDK scaffold for `successfactors`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/successfactors`
- Health endpoint: `/source-runtimes/health?source_id=successfactors`
- Source health receipt: `sources/successfactors/source_health_receipt.json`
- EvidenceCAS reference kind: `successfactors.evidence_cas_reference`

## Families

- `users`, emits `successfactors.users`, reads `/v1/users`
- `accounts`, emits `successfactors.accounts`, reads `/v1/accounts`
- `records`, emits `successfactors.records`, reads `/v1/records`
- `policies`, emits `successfactors.policies`, reads `/v1/policies`
- `audit_events`, emits `successfactors.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/successfactors ./internal/sourceprojection -count=1`
- `make catalog-check`
