# Keeper

Generated Source Runtime SDK scaffold for `keeper`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/keeper`
- Health endpoint: `/source-runtimes/health?source_id=keeper`
- Source health receipt: `sources/keeper/source_health_receipt.json`
- EvidenceCAS reference kind: `keeper.evidence_cas_reference`

## Families

- `users`, emits `keeper.users`, reads `/v1/users`
- `secrets`, emits `keeper.secrets`, reads `/v1/secrets`
- `audit_events`, emits `keeper.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/keeper ./internal/sourceprojection -count=1`
- `make catalog-check`
