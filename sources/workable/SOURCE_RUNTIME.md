# Workable

Generated Source Runtime SDK scaffold for `workable`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/workable`
- Health endpoint: `/source-runtimes/health?source_id=workable`
- Source health receipt: `sources/workable/source_health_receipt.json`
- EvidenceCAS reference kind: `workable.evidence_cas_reference`

## Families

- `users`, emits `workable.users`, reads `/v1/users`
- `accounts`, emits `workable.accounts`, reads `/v1/accounts`
- `records`, emits `workable.records`, reads `/v1/records`
- `policies`, emits `workable.policies`, reads `/v1/policies`
- `audit_events`, emits `workable.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/workable ./internal/sourceprojection -count=1`
- `make catalog-check`
