# Klaviyo

Generated Source Runtime SDK scaffold for `klaviyo`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/klaviyo`
- Health endpoint: `/source-runtimes/health?source_id=klaviyo`
- Source health receipt: `sources/klaviyo/source_health_receipt.json`
- EvidenceCAS reference kind: `klaviyo.evidence_cas_reference`

## Families

- `users`, emits `klaviyo.users`, reads `/v1/users`
- `accounts`, emits `klaviyo.accounts`, reads `/v1/accounts`
- `records`, emits `klaviyo.records`, reads `/v1/records`
- `policies`, emits `klaviyo.policies`, reads `/v1/policies`
- `audit_events`, emits `klaviyo.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/klaviyo ./internal/sourceprojection -count=1`
- `make catalog-check`
