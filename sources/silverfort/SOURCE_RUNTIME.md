# Silverfort

Generated Source Runtime SDK scaffold for `silverfort`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/silverfort`
- Health endpoint: `/source-runtimes/health?source_id=silverfort`
- Source health receipt: `sources/silverfort/source_health_receipt.json`
- EvidenceCAS reference kind: `silverfort.evidence_cas_reference`

## Families

- `users`, emits `silverfort.users`, reads `/v1/users`
- `groups`, emits `silverfort.groups`, reads `/v1/groups`
- `roles`, emits `silverfort.roles`, reads `/v1/roles`
- `applications`, emits `silverfort.applications`, reads `/v1/applications`
- `audit_events`, emits `silverfort.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/silverfort ./internal/sourceprojection -count=1`
- `make catalog-check`
