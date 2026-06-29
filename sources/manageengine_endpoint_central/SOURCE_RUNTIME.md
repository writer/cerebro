# Manageengine Endpoint Central

Generated Source Runtime SDK scaffold for `manageengine_endpoint_central`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/manageengine_endpoint_central`
- Health endpoint: `/source-runtimes/health?source_id=manageengine_endpoint_central`
- Source health receipt: `sources/manageengine_endpoint_central/source_health_receipt.json`
- EvidenceCAS reference kind: `manageengine_endpoint_central.evidence_cas_reference`

## Families

- `users`, emits `manageengine_endpoint_central.users`, reads `/v1/users`
- `groups`, emits `manageengine_endpoint_central.groups`, reads `/v1/groups`
- `roles`, emits `manageengine_endpoint_central.roles`, reads `/v1/roles`
- `applications`, emits `manageengine_endpoint_central.applications`, reads `/v1/applications`
- `audit_events`, emits `manageengine_endpoint_central.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/manageengine_endpoint_central ./internal/sourceprojection -count=1`
- `make catalog-check`
