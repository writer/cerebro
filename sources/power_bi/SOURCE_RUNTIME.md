# Power Bi

Generated Source Runtime SDK scaffold for `power_bi`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/power_bi`
- Health endpoint: `/source-runtimes/health?source_id=power_bi`
- Source health receipt: `sources/power_bi/source_health_receipt.json`
- EvidenceCAS reference kind: `power_bi.evidence_cas_reference`

## Families

- `users`, emits `power_bi.users`, reads `/v1/users`
- `accounts`, emits `power_bi.accounts`, reads `/v1/accounts`
- `records`, emits `power_bi.records`, reads `/v1/records`
- `policies`, emits `power_bi.policies`, reads `/v1/policies`
- `audit_events`, emits `power_bi.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/power_bi ./internal/sourceprojection -count=1`
- `make catalog-check`
