# Demandbase

Generated Source Runtime SDK scaffold for `demandbase`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/demandbase`
- Health endpoint: `/source-runtimes/health?source_id=demandbase`
- Source health receipt: `sources/demandbase/source_health_receipt.json`
- EvidenceCAS reference kind: `demandbase.evidence_cas_reference`

## Families

- `users`, emits `demandbase.users`, reads `/v1/users`
- `accounts`, emits `demandbase.accounts`, reads `/v1/accounts`
- `records`, emits `demandbase.records`, reads `/v1/records`
- `policies`, emits `demandbase.policies`, reads `/v1/policies`
- `audit_events`, emits `demandbase.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/demandbase ./internal/sourceprojection -count=1`
- `make catalog-check`
