# Box

Generated Source Runtime SDK scaffold for `box`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/box`
- Health endpoint: `/source-runtimes/health?source_id=box`
- Source health receipt: `sources/box/source_health_receipt.json`
- EvidenceCAS reference kind: `box.evidence_cas_reference`

## Families

- `users`, emits `box.users`, reads `/v1/users`
- `content_assets`, emits `box.content_assets`, reads `/v1/resources`
- `audit_events`, emits `box.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/box ./internal/sourceprojection -count=1`
- `make catalog-check`
