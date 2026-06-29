# StrongDM

Generated Source Runtime SDK scaffold for `strongdm`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/strongdm`
- Health endpoint: `/source-runtimes/health?source_id=strongdm`
- Source health receipt: `sources/strongdm/source_health_receipt.json`
- EvidenceCAS reference kind: `strongdm.evidence_cas_reference`

## Families

- `users`, emits `strongdm.users`, reads `/v1/users`
- `groups`, emits `strongdm.groups`, reads `/v1/groups`
- `audit_events`, emits `strongdm.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/strongdm ./internal/sourceprojection -count=1`
- `make catalog-check`
