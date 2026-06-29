# Saleshood

Generated Source Runtime SDK scaffold for `saleshood`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/saleshood`
- Health endpoint: `/source-runtimes/health?source_id=saleshood`
- Source health receipt: `sources/saleshood/source_health_receipt.json`
- EvidenceCAS reference kind: `saleshood.evidence_cas_reference`

## Families

- `users`, emits `saleshood.users`, reads `/v1/users`
- `accounts`, emits `saleshood.accounts`, reads `/v1/accounts`
- `records`, emits `saleshood.records`, reads `/v1/records`
- `policies`, emits `saleshood.policies`, reads `/v1/policies`
- `audit_events`, emits `saleshood.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/saleshood ./internal/sourceprojection -count=1`
- `make catalog-check`
