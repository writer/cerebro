# Ashby

Generated Source Runtime SDK scaffold for `ashby`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ashby`
- Health endpoint: `/source-runtimes/health?source_id=ashby`
- Source health receipt: `sources/ashby/source_health_receipt.json`
- EvidenceCAS reference kind: `ashby.evidence_cas_reference`

## Families

- `users`, emits `ashby.users`, reads `/v1/users`
- `accounts`, emits `ashby.accounts`, reads `/v1/accounts`
- `records`, emits `ashby.records`, reads `/v1/records`
- `policies`, emits `ashby.policies`, reads `/v1/policies`
- `audit_events`, emits `ashby.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/ashby ./internal/sourceprojection -count=1`
- `make catalog-check`
