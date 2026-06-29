# Ceridian Dayforce

Generated Source Runtime SDK scaffold for `ceridian_dayforce`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ceridian_dayforce`
- Health endpoint: `/source-runtimes/health?source_id=ceridian_dayforce`
- Source health receipt: `sources/ceridian_dayforce/source_health_receipt.json`
- EvidenceCAS reference kind: `ceridian_dayforce.evidence_cas_reference`

## Families

- `users`, emits `ceridian_dayforce.users`, reads `/v1/users`
- `accounts`, emits `ceridian_dayforce.accounts`, reads `/v1/accounts`
- `records`, emits `ceridian_dayforce.records`, reads `/v1/records`
- `policies`, emits `ceridian_dayforce.policies`, reads `/v1/policies`
- `audit_events`, emits `ceridian_dayforce.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/ceridian_dayforce ./internal/sourceprojection -count=1`
- `make catalog-check`
