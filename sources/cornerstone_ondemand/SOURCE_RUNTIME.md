# Cornerstone Ondemand

Generated Source Runtime SDK scaffold for `cornerstone_ondemand`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cornerstone_ondemand`
- Health endpoint: `/source-runtimes/health?source_id=cornerstone_ondemand`
- Source health receipt: `sources/cornerstone_ondemand/source_health_receipt.json`
- EvidenceCAS reference kind: `cornerstone_ondemand.evidence_cas_reference`

## Families

- `users`, emits `cornerstone_ondemand.users`, reads `/v1/users`
- `accounts`, emits `cornerstone_ondemand.accounts`, reads `/v1/accounts`
- `records`, emits `cornerstone_ondemand.records`, reads `/v1/records`
- `policies`, emits `cornerstone_ondemand.policies`, reads `/v1/policies`
- `audit_events`, emits `cornerstone_ondemand.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cornerstone_ondemand ./internal/sourceprojection -count=1`
- `make catalog-check`
