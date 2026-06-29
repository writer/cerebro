# Omni Analytics

Generated Source Runtime SDK scaffold for `omni_analytics`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/omni_analytics`
- Health endpoint: `/source-runtimes/health?source_id=omni_analytics`
- Source health receipt: `sources/omni_analytics/source_health_receipt.json`
- EvidenceCAS reference kind: `omni_analytics.evidence_cas_reference`

## Families

- `users`, emits `omni_analytics.users`, reads `/v1/users`
- `accounts`, emits `omni_analytics.accounts`, reads `/v1/accounts`
- `records`, emits `omni_analytics.records`, reads `/v1/records`
- `policies`, emits `omni_analytics.policies`, reads `/v1/policies`
- `audit_events`, emits `omni_analytics.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/omni_analytics ./internal/sourceprojection -count=1`
- `make catalog-check`
