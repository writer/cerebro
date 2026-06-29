# Keycloak

Generated Source Runtime SDK scaffold for `keycloak`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/keycloak`
- Health endpoint: `/source-runtimes/health?source_id=keycloak`
- Source health receipt: `sources/keycloak/source_health_receipt.json`
- EvidenceCAS reference kind: `keycloak.evidence_cas_reference`

## Families

- `users`, emits `keycloak.users`, reads `/users`
- `groups`, emits `keycloak.groups`, reads `/groups`
- `audit_events`, emits `keycloak.audit_events`, reads `/events`

## Tests

- `go test ./sources/keycloak ./internal/sourceprojection -count=1`
- `make catalog-check`
