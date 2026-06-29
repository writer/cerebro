# Recurly

Generated Source Runtime SDK scaffold for `recurly`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/recurly`
- Health endpoint: `/source-runtimes/health?source_id=recurly`
- Source health receipt: `sources/recurly/source_health_receipt.json`
- EvidenceCAS reference kind: `recurly.evidence_cas_reference`

## Families

- `users`, emits `recurly.users`, reads `/v1/users`
- `accounts`, emits `recurly.accounts`, reads `/v1/accounts`
- `records`, emits `recurly.records`, reads `/v1/records`
- `policies`, emits `recurly.policies`, reads `/v1/policies`
- `audit_events`, emits `recurly.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/recurly ./internal/sourceprojection -count=1`
- `make catalog-check`
