# Concur

Generated Source Runtime SDK scaffold for `concur`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/concur`
- Health endpoint: `/source-runtimes/health?source_id=concur`
- Source health receipt: `sources/concur/source_health_receipt.json`
- EvidenceCAS reference kind: `concur.evidence_cas_reference`

## Families

- `users`, emits `concur.users`, reads `/v1/users`
- `accounts`, emits `concur.accounts`, reads `/v1/accounts`
- `records`, emits `concur.records`, reads `/v1/records`
- `policies`, emits `concur.policies`, reads `/v1/policies`
- `audit_events`, emits `concur.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/concur ./internal/sourceprojection -count=1`
- `make catalog-check`
