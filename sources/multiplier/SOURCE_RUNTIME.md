# Multiplier

Generated Source Runtime SDK scaffold for `multiplier`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/multiplier`
- Health endpoint: `/source-runtimes/health?source_id=multiplier`
- Source health receipt: `sources/multiplier/source_health_receipt.json`
- EvidenceCAS reference kind: `multiplier.evidence_cas_reference`

## Families

- `users`, emits `multiplier.users`, reads `/v1/users`
- `accounts`, emits `multiplier.accounts`, reads `/v1/accounts`
- `records`, emits `multiplier.records`, reads `/v1/records`
- `policies`, emits `multiplier.policies`, reads `/v1/policies`
- `audit_events`, emits `multiplier.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/multiplier ./internal/sourceprojection -count=1`
- `make catalog-check`
