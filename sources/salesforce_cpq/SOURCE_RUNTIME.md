# Salesforce Cpq

Generated Source Runtime SDK scaffold for `salesforce_cpq`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/salesforce_cpq`
- Health endpoint: `/source-runtimes/health?source_id=salesforce_cpq`
- Source health receipt: `sources/salesforce_cpq/source_health_receipt.json`
- EvidenceCAS reference kind: `salesforce_cpq.evidence_cas_reference`

## Families

- `users`, emits `salesforce_cpq.users`, reads `/v1/users`
- `accounts`, emits `salesforce_cpq.accounts`, reads `/v1/accounts`
- `records`, emits `salesforce_cpq.records`, reads `/v1/records`
- `policies`, emits `salesforce_cpq.policies`, reads `/v1/policies`
- `audit_events`, emits `salesforce_cpq.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/salesforce_cpq ./internal/sourceprojection -count=1`
- `make catalog-check`
