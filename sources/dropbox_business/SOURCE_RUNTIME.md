# Dropbox Business

Generated Source Runtime SDK scaffold for `dropbox_business`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/dropbox_business`
- Health endpoint: `/source-runtimes/health?source_id=dropbox_business`
- Source health receipt: `sources/dropbox_business/source_health_receipt.json`
- EvidenceCAS reference kind: `dropbox_business.evidence_cas_reference`

## Families

- `users`, emits `dropbox_business.users`, reads `/v1/users`
- `content_assets`, emits `dropbox_business.content_assets`, reads `/v1/resources`
- `audit_events`, emits `dropbox_business.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/dropbox_business ./internal/sourceprojection -count=1`
- `make catalog-check`
