# Namely

Generated Source Runtime SDK scaffold for `namely`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/namely`
- Health endpoint: `/source-runtimes/health?source_id=namely`
- Source health receipt: `sources/namely/source_health_receipt.json`
- EvidenceCAS reference kind: `namely.evidence_cas_reference`

## Families

- `users`, emits `namely.users`, reads `/v1/users`
- `accounts`, emits `namely.accounts`, reads `/v1/accounts`
- `records`, emits `namely.records`, reads `/v1/records`
- `policies`, emits `namely.policies`, reads `/v1/policies`
- `audit_events`, emits `namely.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/namely ./internal/sourceprojection -count=1`
- `make catalog-check`
