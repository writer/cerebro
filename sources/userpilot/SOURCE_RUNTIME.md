# Userpilot

Generated Source Runtime SDK scaffold for `userpilot`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/userpilot`
- Health endpoint: `/source-runtimes/health?source_id=userpilot`
- Source health receipt: `sources/userpilot/source_health_receipt.json`
- EvidenceCAS reference kind: `userpilot.evidence_cas_reference`

## Families

- `users`, emits `userpilot.users`, reads `/v1/users`
- `accounts`, emits `userpilot.accounts`, reads `/v1/accounts`
- `records`, emits `userpilot.records`, reads `/v1/records`
- `policies`, emits `userpilot.policies`, reads `/v1/policies`
- `audit_events`, emits `userpilot.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/userpilot ./internal/sourceprojection -count=1`
- `make catalog-check`
