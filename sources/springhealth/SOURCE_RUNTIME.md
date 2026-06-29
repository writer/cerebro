# Springhealth

Generated Source Runtime SDK scaffold for `springhealth`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/springhealth`
- Health endpoint: `/source-runtimes/health?source_id=springhealth`
- Source health receipt: `sources/springhealth/source_health_receipt.json`
- EvidenceCAS reference kind: `springhealth.evidence_cas_reference`

## Families

- `users`, emits `springhealth.users`, reads `/v1/users`
- `accounts`, emits `springhealth.accounts`, reads `/v1/accounts`
- `records`, emits `springhealth.records`, reads `/v1/records`
- `policies`, emits `springhealth.policies`, reads `/v1/policies`
- `audit_events`, emits `springhealth.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/springhealth ./internal/sourceprojection -count=1`
- `make catalog-check`
