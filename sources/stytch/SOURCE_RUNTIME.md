# Stytch

Generated Source Runtime SDK scaffold for `stytch`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/stytch`
- Health endpoint: `/source-runtimes/health?source_id=stytch`
- Source health receipt: `sources/stytch/source_health_receipt.json`
- EvidenceCAS reference kind: `stytch.evidence_cas_reference`

## Families

- `users`, emits `stytch.users`, reads `/v1/users`
- `groups`, emits `stytch.groups`, reads `/v1/groups`
- `roles`, emits `stytch.roles`, reads `/v1/roles`
- `applications`, emits `stytch.applications`, reads `/v1/applications`
- `audit_events`, emits `stytch.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/stytch ./internal/sourceprojection -count=1`
- `make catalog-check`
