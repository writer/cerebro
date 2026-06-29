# Nordlayer

Generated Source Runtime SDK scaffold for `nordlayer`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/nordlayer`
- Health endpoint: `/source-runtimes/health?source_id=nordlayer`
- Source health receipt: `sources/nordlayer/source_health_receipt.json`
- EvidenceCAS reference kind: `nordlayer.evidence_cas_reference`

## Families

- `users`, emits `nordlayer.users`, reads `/v1/users`
- `groups`, emits `nordlayer.groups`, reads `/v1/groups`
- `roles`, emits `nordlayer.roles`, reads `/v1/roles`
- `applications`, emits `nordlayer.applications`, reads `/v1/applications`
- `audit_events`, emits `nordlayer.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/nordlayer ./internal/sourceprojection -count=1`
- `make catalog-check`
