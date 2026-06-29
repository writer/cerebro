# Sage Intacct

Generated Source Runtime SDK scaffold for `sage_intacct`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sage_intacct`
- Health endpoint: `/source-runtimes/health?source_id=sage_intacct`
- Source health receipt: `sources/sage_intacct/source_health_receipt.json`
- EvidenceCAS reference kind: `sage_intacct.evidence_cas_reference`

## Families

- `users`, emits `sage_intacct.users`, reads `/v1/users`
- `accounts`, emits `sage_intacct.accounts`, reads `/v1/accounts`
- `records`, emits `sage_intacct.records`, reads `/v1/records`
- `policies`, emits `sage_intacct.policies`, reads `/v1/policies`
- `audit_events`, emits `sage_intacct.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sage_intacct ./internal/sourceprojection -count=1`
- `make catalog-check`
