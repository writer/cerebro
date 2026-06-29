# Teleport

Generated Source Runtime SDK scaffold for `teleport`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/teleport`
- Health endpoint: `/source-runtimes/health?source_id=teleport`
- Source health receipt: `sources/teleport/source_health_receipt.json`
- EvidenceCAS reference kind: `teleport.evidence_cas_reference`

## Families

- `users`, emits `teleport.users`, reads `/v1/users`
- `groups`, emits `teleport.groups`, reads `/v1/groups`
- `audit_events`, emits `teleport.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/teleport ./internal/sourceprojection -count=1`
- `make catalog-check`
