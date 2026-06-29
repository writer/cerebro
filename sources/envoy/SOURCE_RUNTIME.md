# Envoy

Generated Source Runtime SDK scaffold for `envoy`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/envoy`
- Health endpoint: `/source-runtimes/health?source_id=envoy`
- Source health receipt: `sources/envoy/source_health_receipt.json`
- EvidenceCAS reference kind: `envoy.evidence_cas_reference`

## Families

- `users`, emits `envoy.users`, reads `/v1/users`
- `groups`, emits `envoy.groups`, reads `/v1/groups`
- `workspaces`, emits `envoy.workspaces`, reads `/v1/workspaces`
- `documents`, emits `envoy.documents`, reads `/v1/documents`
- `audit_events`, emits `envoy.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/envoy ./internal/sourceprojection -count=1`
- `make catalog-check`
