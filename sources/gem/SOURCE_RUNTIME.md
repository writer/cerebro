# Gem

Generated Source Runtime SDK scaffold for `gem`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gem`
- Health endpoint: `/source-runtimes/health?source_id=gem`
- Source health receipt: `sources/gem/source_health_receipt.json`
- EvidenceCAS reference kind: `gem.evidence_cas_reference`

## Families

- `users`, emits `gem.users`, reads `/v1/users`
- `accounts`, emits `gem.accounts`, reads `/v1/accounts`
- `records`, emits `gem.records`, reads `/v1/records`
- `policies`, emits `gem.policies`, reads `/v1/policies`
- `audit_events`, emits `gem.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/gem ./internal/sourceprojection -count=1`
- `make catalog-check`
