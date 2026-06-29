# Spendesk

Generated Source Runtime SDK scaffold for `spendesk`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/spendesk`
- Health endpoint: `/source-runtimes/health?source_id=spendesk`
- Source health receipt: `sources/spendesk/source_health_receipt.json`
- EvidenceCAS reference kind: `spendesk.evidence_cas_reference`

## Families

- `users`, emits `spendesk.users`, reads `/v1/users`
- `accounts`, emits `spendesk.accounts`, reads `/v1/accounts`
- `records`, emits `spendesk.records`, reads `/v1/records`
- `policies`, emits `spendesk.policies`, reads `/v1/policies`
- `audit_events`, emits `spendesk.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/spendesk ./internal/sourceprojection -count=1`
- `make catalog-check`
