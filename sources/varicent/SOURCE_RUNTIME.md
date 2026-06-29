# Varicent

Generated Source Runtime SDK scaffold for `varicent`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/varicent`
- Health endpoint: `/source-runtimes/health?source_id=varicent`
- Source health receipt: `sources/varicent/source_health_receipt.json`
- EvidenceCAS reference kind: `varicent.evidence_cas_reference`

## Families

- `users`, emits `varicent.users`, reads `/v1/users`
- `accounts`, emits `varicent.accounts`, reads `/v1/accounts`
- `records`, emits `varicent.records`, reads `/v1/records`
- `policies`, emits `varicent.policies`, reads `/v1/policies`
- `audit_events`, emits `varicent.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/varicent ./internal/sourceprojection -count=1`
- `make catalog-check`
