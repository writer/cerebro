# Zenefits

Generated Source Runtime SDK scaffold for `zenefits`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zenefits`
- Health endpoint: `/source-runtimes/health?source_id=zenefits`
- Source health receipt: `sources/zenefits/source_health_receipt.json`
- EvidenceCAS reference kind: `zenefits.evidence_cas_reference`

## Families

- `users`, emits `zenefits.users`, reads `/v1/users`
- `accounts`, emits `zenefits.accounts`, reads `/v1/accounts`
- `records`, emits `zenefits.records`, reads `/v1/records`
- `policies`, emits `zenefits.policies`, reads `/v1/policies`
- `audit_events`, emits `zenefits.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zenefits ./internal/sourceprojection -count=1`
- `make catalog-check`
