# Callrail

Generated Source Runtime SDK scaffold for `callrail`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/callrail`
- Health endpoint: `/source-runtimes/health?source_id=callrail`
- Source health receipt: `sources/callrail/source_health_receipt.json`
- EvidenceCAS reference kind: `callrail.evidence_cas_reference`

## Families

- `users`, emits `callrail.users`, reads `/v1/users`
- `accounts`, emits `callrail.accounts`, reads `/v1/accounts`
- `records`, emits `callrail.records`, reads `/v1/records`
- `policies`, emits `callrail.policies`, reads `/v1/policies`
- `audit_events`, emits `callrail.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/callrail ./internal/sourceprojection -count=1`
- `make catalog-check`
