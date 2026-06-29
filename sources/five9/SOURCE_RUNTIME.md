# Five9

Generated Source Runtime SDK scaffold for `five9`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/five9`
- Health endpoint: `/source-runtimes/health?source_id=five9`
- Source health receipt: `sources/five9/source_health_receipt.json`
- EvidenceCAS reference kind: `five9.evidence_cas_reference`

## Families

- `users`, emits `five9.users`, reads `/v1/users`
- `accounts`, emits `five9.accounts`, reads `/v1/accounts`
- `records`, emits `five9.records`, reads `/v1/records`
- `policies`, emits `five9.policies`, reads `/v1/policies`
- `audit_events`, emits `five9.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/five9 ./internal/sourceprojection -count=1`
- `make catalog-check`
