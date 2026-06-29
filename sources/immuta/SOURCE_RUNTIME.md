# Immuta

Generated Source Runtime SDK scaffold for `immuta`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/immuta`
- Health endpoint: `/source-runtimes/health?source_id=immuta`
- Source health receipt: `sources/immuta/source_health_receipt.json`
- EvidenceCAS reference kind: `immuta.evidence_cas_reference`

## Families

- `users`, emits `immuta.users`, reads `/v1/users`
- `accounts`, emits `immuta.accounts`, reads `/v1/accounts`
- `records`, emits `immuta.records`, reads `/v1/records`
- `policies`, emits `immuta.policies`, reads `/v1/policies`
- `audit_events`, emits `immuta.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/immuta ./internal/sourceprojection -count=1`
- `make catalog-check`
