# Smartrecruiters

Generated Source Runtime SDK scaffold for `smartrecruiters`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/smartrecruiters`
- Health endpoint: `/source-runtimes/health?source_id=smartrecruiters`
- Source health receipt: `sources/smartrecruiters/source_health_receipt.json`
- EvidenceCAS reference kind: `smartrecruiters.evidence_cas_reference`

## Families

- `users`, emits `smartrecruiters.users`, reads `/v1/users`
- `accounts`, emits `smartrecruiters.accounts`, reads `/v1/accounts`
- `records`, emits `smartrecruiters.records`, reads `/v1/records`
- `policies`, emits `smartrecruiters.policies`, reads `/v1/policies`
- `audit_events`, emits `smartrecruiters.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/smartrecruiters ./internal/sourceprojection -count=1`
- `make catalog-check`
