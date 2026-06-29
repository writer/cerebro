# Formstack

Generated Source Runtime SDK scaffold for `formstack`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/formstack`
- Health endpoint: `/source-runtimes/health?source_id=formstack`
- Source health receipt: `sources/formstack/source_health_receipt.json`
- EvidenceCAS reference kind: `formstack.evidence_cas_reference`

## Families

- `users`, emits `formstack.users`, reads `/v1/users`
- `accounts`, emits `formstack.accounts`, reads `/v1/accounts`
- `records`, emits `formstack.records`, reads `/v1/records`
- `policies`, emits `formstack.policies`, reads `/v1/policies`
- `audit_events`, emits `formstack.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/formstack ./internal/sourceprojection -count=1`
- `make catalog-check`
