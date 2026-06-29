# Fifteenfive

Generated Source Runtime SDK scaffold for `fifteenfive`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fifteenfive`
- Health endpoint: `/source-runtimes/health?source_id=fifteenfive`
- Source health receipt: `sources/fifteenfive/source_health_receipt.json`
- EvidenceCAS reference kind: `fifteenfive.evidence_cas_reference`

## Families

- `users`, emits `fifteenfive.users`, reads `/v1/users`
- `accounts`, emits `fifteenfive.accounts`, reads `/v1/accounts`
- `records`, emits `fifteenfive.records`, reads `/v1/records`
- `policies`, emits `fifteenfive.policies`, reads `/v1/policies`
- `audit_events`, emits `fifteenfive.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/fifteenfive ./internal/sourceprojection -count=1`
- `make catalog-check`
