# Envoy Visitors

Generated Source Runtime SDK scaffold for `envoy_visitors`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/envoy_visitors`
- Health endpoint: `/source-runtimes/health?source_id=envoy_visitors`
- Source health receipt: `sources/envoy_visitors/source_health_receipt.json`
- EvidenceCAS reference kind: `envoy_visitors.evidence_cas_reference`

## Families

- `users`, emits `envoy_visitors.users`, reads `/v1/users`
- `accounts`, emits `envoy_visitors.accounts`, reads `/v1/accounts`
- `records`, emits `envoy_visitors.records`, reads `/v1/records`
- `policies`, emits `envoy_visitors.policies`, reads `/v1/policies`
- `audit_events`, emits `envoy_visitors.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/envoy_visitors ./internal/sourceprojection -count=1`
- `make catalog-check`
