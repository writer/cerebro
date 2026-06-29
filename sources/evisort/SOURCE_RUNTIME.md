# Evisort

Generated Source Runtime SDK scaffold for `evisort`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/evisort`
- Health endpoint: `/source-runtimes/health?source_id=evisort`
- Source health receipt: `sources/evisort/source_health_receipt.json`
- EvidenceCAS reference kind: `evisort.evidence_cas_reference`

## Families

- `users`, emits `evisort.users`, reads `/v1/users`
- `accounts`, emits `evisort.accounts`, reads `/v1/accounts`
- `records`, emits `evisort.records`, reads `/v1/records`
- `policies`, emits `evisort.policies`, reads `/v1/policies`
- `audit_events`, emits `evisort.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/evisort ./internal/sourceprojection -count=1`
- `make catalog-check`
