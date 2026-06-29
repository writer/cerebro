# Hexnode

Generated Source Runtime SDK scaffold for `hexnode`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hexnode`
- Health endpoint: `/source-runtimes/health?source_id=hexnode`
- Source health receipt: `sources/hexnode/source_health_receipt.json`
- EvidenceCAS reference kind: `hexnode.evidence_cas_reference`

## Families

- `users`, emits `hexnode.users`, reads `/v1/users`
- `groups`, emits `hexnode.groups`, reads `/v1/groups`
- `roles`, emits `hexnode.roles`, reads `/v1/roles`
- `applications`, emits `hexnode.applications`, reads `/v1/applications`
- `audit_events`, emits `hexnode.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/hexnode ./internal/sourceprojection -count=1`
- `make catalog-check`
