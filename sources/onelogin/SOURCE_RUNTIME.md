# OneLogin

Generated Source Runtime SDK scaffold for `onelogin`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/onelogin`
- Health endpoint: `/source-runtimes/health?source_id=onelogin`
- Source health receipt: `sources/onelogin/source_health_receipt.json`
- EvidenceCAS reference kind: `onelogin.evidence_cas_reference`

## Families

- `users`, emits `onelogin.users`, reads `/v1/users`
- `groups`, emits `onelogin.groups`, reads `/v1/groups`
- `audit_events`, emits `onelogin.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/onelogin ./internal/sourceprojection -count=1`
- `make catalog-check`
