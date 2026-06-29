# Freshbooks

Generated Source Runtime SDK scaffold for `freshbooks`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/freshbooks`
- Health endpoint: `/source-runtimes/health?source_id=freshbooks`
- Source health receipt: `sources/freshbooks/source_health_receipt.json`
- EvidenceCAS reference kind: `freshbooks.evidence_cas_reference`

## Families

- `users`, emits `freshbooks.users`, reads `/v1/users`
- `accounts`, emits `freshbooks.accounts`, reads `/v1/accounts`
- `records`, emits `freshbooks.records`, reads `/v1/records`
- `policies`, emits `freshbooks.policies`, reads `/v1/policies`
- `audit_events`, emits `freshbooks.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/freshbooks ./internal/sourceprojection -count=1`
- `make catalog-check`
