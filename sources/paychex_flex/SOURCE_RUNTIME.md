# Paychex Flex

Generated Source Runtime SDK scaffold for `paychex_flex`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/paychex_flex`
- Health endpoint: `/source-runtimes/health?source_id=paychex_flex`
- Source health receipt: `sources/paychex_flex/source_health_receipt.json`
- EvidenceCAS reference kind: `paychex_flex.evidence_cas_reference`

## Families

- `users`, emits `paychex_flex.users`, reads `/v1/users`
- `accounts`, emits `paychex_flex.accounts`, reads `/v1/accounts`
- `records`, emits `paychex_flex.records`, reads `/v1/records`
- `policies`, emits `paychex_flex.policies`, reads `/v1/policies`
- `audit_events`, emits `paychex_flex.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/paychex_flex ./internal/sourceprojection -count=1`
- `make catalog-check`
