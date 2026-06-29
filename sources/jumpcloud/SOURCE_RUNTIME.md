# JumpCloud

Generated Source Runtime SDK scaffold for `jumpcloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/jumpcloud`
- Health endpoint: `/source-runtimes/health?source_id=jumpcloud`
- Source health receipt: `sources/jumpcloud/source_health_receipt.json`
- EvidenceCAS reference kind: `jumpcloud.evidence_cas_reference`

## Families

- `users`, emits `jumpcloud.users`, reads `/v1/users`
- `groups`, emits `jumpcloud.groups`, reads `/v1/groups`
- `audit_events`, emits `jumpcloud.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/jumpcloud ./internal/sourceprojection -count=1`
- `make catalog-check`
