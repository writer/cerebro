# Typeform

Generated Source Runtime SDK scaffold for `typeform`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/typeform`
- Health endpoint: `/source-runtimes/health?source_id=typeform`
- Source health receipt: `sources/typeform/source_health_receipt.json`
- EvidenceCAS reference kind: `typeform.evidence_cas_reference`

## Families

- `users`, emits `typeform.users`, reads `/v1/users`
- `accounts`, emits `typeform.accounts`, reads `/v1/accounts`
- `records`, emits `typeform.records`, reads `/v1/records`
- `policies`, emits `typeform.policies`, reads `/v1/policies`
- `audit_events`, emits `typeform.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/typeform ./internal/sourceprojection -count=1`
- `make catalog-check`
