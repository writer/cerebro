# Auth0

Generated Source Runtime SDK scaffold for `auth0`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/auth0`
- Health endpoint: `/source-runtimes/health?source_id=auth0`
- Source health receipt: `sources/auth0/source_health_receipt.json`
- EvidenceCAS reference kind: `auth0.evidence_cas_reference`

## Families

- `users`, emits `auth0.users`, reads `/users`
- `roles`, emits `auth0.roles`, reads `/roles`
- `audit_events`, emits `auth0.audit_events`, reads `/logs`

## Tests

- `go test ./sources/auth0 ./internal/sourceprojection -count=1`
- `make catalog-check`
