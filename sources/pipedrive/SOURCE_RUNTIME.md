# Pipedrive

Generated Source Runtime SDK scaffold for `pipedrive`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/pipedrive`
- Health endpoint: `/source-runtimes/health?source_id=pipedrive`
- Source health receipt: `sources/pipedrive/source_health_receipt.json`
- EvidenceCAS reference kind: `pipedrive.evidence_cas_reference`

## Families

- `users`, emits `pipedrive.users`, reads `/v1/users`
- `accounts`, emits `pipedrive.accounts`, reads `/v1/accounts`
- `records`, emits `pipedrive.records`, reads `/v1/records`
- `policies`, emits `pipedrive.policies`, reads `/v1/policies`
- `audit_events`, emits `pipedrive.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/pipedrive ./internal/sourceprojection -count=1`
- `make catalog-check`
