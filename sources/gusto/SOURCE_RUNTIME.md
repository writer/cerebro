# Gusto

Generated Source Runtime SDK scaffold for `gusto`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gusto`
- Health endpoint: `/source-runtimes/health?source_id=gusto`
- Source health receipt: `sources/gusto/source_health_receipt.json`
- EvidenceCAS reference kind: `gusto.evidence_cas_reference`

## Families

- `users`, emits `gusto.users`, reads `/v1/users`
- `accounts`, emits `gusto.accounts`, reads `/v1/accounts`
- `records`, emits `gusto.records`, reads `/v1/records`
- `policies`, emits `gusto.policies`, reads `/v1/policies`
- `audit_events`, emits `gusto.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/gusto ./internal/sourceprojection -count=1`
- `make catalog-check`
