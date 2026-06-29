# Mode Analytics

Generated Source Runtime SDK scaffold for `mode_analytics`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mode_analytics`
- Health endpoint: `/source-runtimes/health?source_id=mode_analytics`
- Source health receipt: `sources/mode_analytics/source_health_receipt.json`
- EvidenceCAS reference kind: `mode_analytics.evidence_cas_reference`

## Families

- `users`, emits `mode_analytics.users`, reads `/v1/users`
- `accounts`, emits `mode_analytics.accounts`, reads `/v1/accounts`
- `records`, emits `mode_analytics.records`, reads `/v1/records`
- `policies`, emits `mode_analytics.policies`, reads `/v1/policies`
- `audit_events`, emits `mode_analytics.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/mode_analytics ./internal/sourceprojection -count=1`
- `make catalog-check`
