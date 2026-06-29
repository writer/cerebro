# Outreach

Generated Source Runtime SDK scaffold for `outreach`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/outreach`
- Health endpoint: `/source-runtimes/health?source_id=outreach`
- Source health receipt: `sources/outreach/source_health_receipt.json`
- EvidenceCAS reference kind: `outreach.evidence_cas_reference`

## Families

- `users`, emits `outreach.users`, reads `/v1/users`
- `accounts`, emits `outreach.accounts`, reads `/v1/accounts`
- `records`, emits `outreach.records`, reads `/v1/records`
- `policies`, emits `outreach.policies`, reads `/v1/policies`
- `audit_events`, emits `outreach.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/outreach ./internal/sourceprojection -count=1`
- `make catalog-check`
