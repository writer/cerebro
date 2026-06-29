# Beeline

Generated Source Runtime SDK scaffold for `beeline`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/beeline`
- Health endpoint: `/source-runtimes/health?source_id=beeline`
- Source health receipt: `sources/beeline/source_health_receipt.json`
- EvidenceCAS reference kind: `beeline.evidence_cas_reference`

## Families

- `users`, emits `beeline.users`, reads `/v1/users`
- `accounts`, emits `beeline.accounts`, reads `/v1/accounts`
- `records`, emits `beeline.records`, reads `/v1/records`
- `policies`, emits `beeline.policies`, reads `/v1/policies`
- `audit_events`, emits `beeline.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/beeline ./internal/sourceprojection -count=1`
- `make catalog-check`
