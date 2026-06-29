# Amplitude

Generated Source Runtime SDK scaffold for `amplitude`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/amplitude`
- Health endpoint: `/source-runtimes/health?source_id=amplitude`
- Source health receipt: `sources/amplitude/source_health_receipt.json`
- EvidenceCAS reference kind: `amplitude.evidence_cas_reference`

## Families

- `users`, emits `amplitude.users`, reads `/v1/users`
- `accounts`, emits `amplitude.accounts`, reads `/v1/accounts`
- `records`, emits `amplitude.records`, reads `/v1/records`
- `policies`, emits `amplitude.policies`, reads `/v1/policies`
- `audit_events`, emits `amplitude.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/amplitude ./internal/sourceprojection -count=1`
- `make catalog-check`
