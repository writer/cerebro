# Google Analytics 360

Generated Source Runtime SDK scaffold for `google_analytics_360`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/google_analytics_360`
- Health endpoint: `/source-runtimes/health?source_id=google_analytics_360`
- Source health receipt: `sources/google_analytics_360/source_health_receipt.json`
- EvidenceCAS reference kind: `google_analytics_360.evidence_cas_reference`

## Families

- `users`, emits `google_analytics_360.users`, reads `/v1/users`
- `accounts`, emits `google_analytics_360.accounts`, reads `/v1/accounts`
- `records`, emits `google_analytics_360.records`, reads `/v1/records`
- `policies`, emits `google_analytics_360.policies`, reads `/v1/policies`
- `audit_events`, emits `google_analytics_360.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/google_analytics_360 ./internal/sourceprojection -count=1`
- `make catalog-check`
