# Collibra

Generated Source Runtime SDK scaffold for `collibra`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/collibra`
- Health endpoint: `/source-runtimes/health?source_id=collibra`
- Source health receipt: `sources/collibra/source_health_receipt.json`
- EvidenceCAS reference kind: `collibra.evidence_cas_reference`

## Families

- `users`, emits `collibra.users`, reads `/v1/users`
- `accounts`, emits `collibra.accounts`, reads `/v1/accounts`
- `records`, emits `collibra.records`, reads `/v1/records`
- `policies`, emits `collibra.policies`, reads `/v1/policies`
- `audit_events`, emits `collibra.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/collibra ./internal/sourceprojection -count=1`
- `make catalog-check`
