# Marketo

Generated Source Runtime SDK scaffold for `marketo`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/marketo`
- Health endpoint: `/source-runtimes/health?source_id=marketo`
- Source health receipt: `sources/marketo/source_health_receipt.json`
- EvidenceCAS reference kind: `marketo.evidence_cas_reference`

## Families

- `users`, emits `marketo.users`, reads `/v1/users`
- `accounts`, emits `marketo.accounts`, reads `/v1/accounts`
- `records`, emits `marketo.records`, reads `/v1/records`
- `policies`, emits `marketo.policies`, reads `/v1/policies`
- `audit_events`, emits `marketo.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/marketo ./internal/sourceprojection -count=1`
- `make catalog-check`
