# Hevo Data

Generated Source Runtime SDK scaffold for `hevo_data`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hevo_data`
- Health endpoint: `/source-runtimes/health?source_id=hevo_data`
- Source health receipt: `sources/hevo_data/source_health_receipt.json`
- EvidenceCAS reference kind: `hevo_data.evidence_cas_reference`

## Families

- `users`, emits `hevo_data.users`, reads `/v1/users`
- `accounts`, emits `hevo_data.accounts`, reads `/v1/accounts`
- `records`, emits `hevo_data.records`, reads `/v1/records`
- `policies`, emits `hevo_data.policies`, reads `/v1/policies`
- `audit_events`, emits `hevo_data.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/hevo_data ./internal/sourceprojection -count=1`
- `make catalog-check`
