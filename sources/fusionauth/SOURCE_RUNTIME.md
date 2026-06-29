# Fusionauth

Generated Source Runtime SDK scaffold for `fusionauth`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fusionauth`
- Health endpoint: `/source-runtimes/health?source_id=fusionauth`
- Source health receipt: `sources/fusionauth/source_health_receipt.json`
- EvidenceCAS reference kind: `fusionauth.evidence_cas_reference`

## Families

- `users`, emits `fusionauth.users`, reads `/v1/users`
- `groups`, emits `fusionauth.groups`, reads `/v1/groups`
- `roles`, emits `fusionauth.roles`, reads `/v1/roles`
- `applications`, emits `fusionauth.applications`, reads `/v1/applications`
- `audit_events`, emits `fusionauth.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/fusionauth ./internal/sourceprojection -count=1`
- `make catalog-check`
