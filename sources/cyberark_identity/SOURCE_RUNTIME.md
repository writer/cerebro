# CyberArk Identity

Generated Source Runtime SDK scaffold for `cyberark_identity`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cyberark_identity`
- Health endpoint: `/source-runtimes/health?source_id=cyberark_identity`
- Source health receipt: `sources/cyberark_identity/source_health_receipt.json`
- EvidenceCAS reference kind: `cyberark_identity.evidence_cas_reference`

## Families

- `users`, emits `cyberark_identity.users`, reads `/v1/users`
- `groups`, emits `cyberark_identity.groups`, reads `/v1/groups`
- `audit_events`, emits `cyberark_identity.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/cyberark_identity ./internal/sourceprojection -count=1`
- `make catalog-check`
