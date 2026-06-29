# Lever

Generated Source Runtime SDK scaffold for `lever`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/lever`
- Health endpoint: `/source-runtimes/health?source_id=lever`
- Source health receipt: `sources/lever/source_health_receipt.json`
- EvidenceCAS reference kind: `lever.evidence_cas_reference`

## Families

- `users`, emits `lever.users`, reads `/v1/users`
- `accounts`, emits `lever.accounts`, reads `/v1/accounts`
- `records`, emits `lever.records`, reads `/v1/records`
- `policies`, emits `lever.policies`, reads `/v1/policies`
- `audit_events`, emits `lever.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/lever ./internal/sourceprojection -count=1`
- `make catalog-check`
