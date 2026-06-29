# Atlan

Generated Source Runtime SDK scaffold for `atlan`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/atlan`
- Health endpoint: `/source-runtimes/health?source_id=atlan`
- Source health receipt: `sources/atlan/source_health_receipt.json`
- EvidenceCAS reference kind: `atlan.evidence_cas_reference`

## Families

- `users`, emits `atlan.users`, reads `/v1/users`
- `accounts`, emits `atlan.accounts`, reads `/v1/accounts`
- `records`, emits `atlan.records`, reads `/v1/records`
- `policies`, emits `atlan.policies`, reads `/v1/policies`
- `audit_events`, emits `atlan.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/atlan ./internal/sourceprojection -count=1`
- `make catalog-check`
