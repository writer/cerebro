# Microsoft 365

Generated Source Runtime SDK scaffold for `microsoft_365`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/microsoft_365`
- Health endpoint: `/source-runtimes/health?source_id=microsoft_365`
- Source health receipt: `sources/microsoft_365/source_health_receipt.json`
- EvidenceCAS reference kind: `microsoft_365.evidence_cas_reference`

## Families

- `users`, emits `microsoft_365.users`, reads `/v1/users`
- `content_assets`, emits `microsoft_365.content_assets`, reads `/v1/resources`
- `audit_events`, emits `microsoft_365.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/microsoft_365 ./internal/sourceprojection -count=1`
- `make catalog-check`
