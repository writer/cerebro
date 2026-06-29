# Paddle

Generated Source Runtime SDK scaffold for `paddle`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/paddle`
- Health endpoint: `/source-runtimes/health?source_id=paddle`
- Source health receipt: `sources/paddle/source_health_receipt.json`
- EvidenceCAS reference kind: `paddle.evidence_cas_reference`

## Families

- `users`, emits `paddle.users`, reads `/v1/users`
- `accounts`, emits `paddle.accounts`, reads `/v1/accounts`
- `records`, emits `paddle.records`, reads `/v1/records`
- `policies`, emits `paddle.policies`, reads `/v1/policies`
- `audit_events`, emits `paddle.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/paddle ./internal/sourceprojection -count=1`
- `make catalog-check`
