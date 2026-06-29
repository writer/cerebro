# Datafold

Generated Source Runtime SDK scaffold for `datafold`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/datafold`
- Health endpoint: `/source-runtimes/health?source_id=datafold`
- Source health receipt: `sources/datafold/source_health_receipt.json`
- EvidenceCAS reference kind: `datafold.evidence_cas_reference`

## Families

- `users`, emits `datafold.users`, reads `/v1/users`
- `accounts`, emits `datafold.accounts`, reads `/v1/accounts`
- `records`, emits `datafold.records`, reads `/v1/records`
- `policies`, emits `datafold.policies`, reads `/v1/policies`
- `audit_events`, emits `datafold.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/datafold ./internal/sourceprojection -count=1`
- `make catalog-check`
