# Revenuecat

Generated Source Runtime SDK scaffold for `revenuecat`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/revenuecat`
- Health endpoint: `/source-runtimes/health?source_id=revenuecat`
- Source health receipt: `sources/revenuecat/source_health_receipt.json`
- EvidenceCAS reference kind: `revenuecat.evidence_cas_reference`

## Families

- `users`, emits `revenuecat.users`, reads `/v1/users`
- `accounts`, emits `revenuecat.accounts`, reads `/v1/accounts`
- `records`, emits `revenuecat.records`, reads `/v1/records`
- `policies`, emits `revenuecat.policies`, reads `/v1/policies`
- `audit_events`, emits `revenuecat.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/revenuecat ./internal/sourceprojection -count=1`
- `make catalog-check`
