# Zoom

Generated Source Runtime SDK scaffold for `zoom`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zoom`
- Health endpoint: `/source-runtimes/health?source_id=zoom`
- Source health receipt: `sources/zoom/source_health_receipt.json`
- EvidenceCAS reference kind: `zoom.evidence_cas_reference`

## Families

- `users`, emits `zoom.users`, reads `/v1/users`
- `content_assets`, emits `zoom.content_assets`, reads `/v1/resources`
- `audit_events`, emits `zoom.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/zoom ./internal/sourceprojection -count=1`
- `make catalog-check`
