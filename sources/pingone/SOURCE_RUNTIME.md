# PingOne

Generated Source Runtime SDK scaffold for `pingone`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/pingone`
- Health endpoint: `/source-runtimes/health?source_id=pingone`
- Source health receipt: `sources/pingone/source_health_receipt.json`
- EvidenceCAS reference kind: `pingone.evidence_cas_reference`

## Families

- `users`, emits `pingone.users`, reads `/v1/users`
- `groups`, emits `pingone.groups`, reads `/v1/groups`
- `audit_events`, emits `pingone.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/pingone ./internal/sourceprojection -count=1`
- `make catalog-check`
