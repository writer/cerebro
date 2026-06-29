# Sailpoint Identitynow

Generated Source Runtime SDK scaffold for `sailpoint_identitynow`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sailpoint_identitynow`
- Health endpoint: `/source-runtimes/health?source_id=sailpoint_identitynow`
- Source health receipt: `sources/sailpoint_identitynow/source_health_receipt.json`
- EvidenceCAS reference kind: `sailpoint_identitynow.evidence_cas_reference`

## Families

- `users`, emits `sailpoint_identitynow.users`, reads `/v1/users`
- `groups`, emits `sailpoint_identitynow.groups`, reads `/v1/groups`
- `roles`, emits `sailpoint_identitynow.roles`, reads `/v1/roles`
- `applications`, emits `sailpoint_identitynow.applications`, reads `/v1/applications`
- `audit_events`, emits `sailpoint_identitynow.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sailpoint_identitynow ./internal/sourceprojection -count=1`
- `make catalog-check`
