# WorkOS

Generated Source Runtime SDK scaffold for `workos`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/workos`
- Health endpoint: `/source-runtimes/health?source_id=workos`
- Source health receipt: `sources/workos/source_health_receipt.json`
- EvidenceCAS reference kind: `workos.evidence_cas_reference`

## Families

- `users`, emits `workos.users`, reads `/users`
- `groups`, emits `workos.groups`, reads `/groups`
- `audit_events`, emits `workos.audit_events`, reads `/events`

## Tests

- `go test ./sources/workos ./internal/sourceprojection -count=1`
- `make catalog-check`
