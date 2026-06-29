# Skillsoft Percipio

Generated Source Runtime SDK scaffold for `skillsoft_percipio`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/skillsoft_percipio`
- Health endpoint: `/source-runtimes/health?source_id=skillsoft_percipio`
- Source health receipt: `sources/skillsoft_percipio/source_health_receipt.json`
- EvidenceCAS reference kind: `skillsoft_percipio.evidence_cas_reference`

## Families

- `users`, emits `skillsoft_percipio.users`, reads `/v1/users`
- `accounts`, emits `skillsoft_percipio.accounts`, reads `/v1/accounts`
- `records`, emits `skillsoft_percipio.records`, reads `/v1/records`
- `policies`, emits `skillsoft_percipio.policies`, reads `/v1/policies`
- `audit_events`, emits `skillsoft_percipio.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/skillsoft_percipio ./internal/sourceprojection -count=1`
- `make catalog-check`
