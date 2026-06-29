# Highspot

Generated Source Runtime SDK scaffold for `highspot`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/highspot`
- Health endpoint: `/source-runtimes/health?source_id=highspot`
- Source health receipt: `sources/highspot/source_health_receipt.json`
- EvidenceCAS reference kind: `highspot.evidence_cas_reference`

## Families

- `users`, emits `highspot.users`, reads `/v1/users`
- `accounts`, emits `highspot.accounts`, reads `/v1/accounts`
- `records`, emits `highspot.records`, reads `/v1/records`
- `policies`, emits `highspot.policies`, reads `/v1/policies`
- `audit_events`, emits `highspot.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/highspot ./internal/sourceprojection -count=1`
- `make catalog-check`
