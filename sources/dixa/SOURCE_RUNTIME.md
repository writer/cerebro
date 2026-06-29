# Dixa

Generated Source Runtime SDK scaffold for `dixa`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/dixa`
- Health endpoint: `/source-runtimes/health?source_id=dixa`
- Source health receipt: `sources/dixa/source_health_receipt.json`
- EvidenceCAS reference kind: `dixa.evidence_cas_reference`

## Families

- `users`, emits `dixa.users`, reads `/v1/users`
- `accounts`, emits `dixa.accounts`, reads `/v1/accounts`
- `records`, emits `dixa.records`, reads `/v1/records`
- `policies`, emits `dixa.policies`, reads `/v1/policies`
- `audit_events`, emits `dixa.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/dixa ./internal/sourceprojection -count=1`
- `make catalog-check`
