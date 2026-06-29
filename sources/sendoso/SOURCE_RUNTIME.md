# Sendoso

Generated Source Runtime SDK scaffold for `sendoso`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sendoso`
- Health endpoint: `/source-runtimes/health?source_id=sendoso`
- Source health receipt: `sources/sendoso/source_health_receipt.json`
- EvidenceCAS reference kind: `sendoso.evidence_cas_reference`

## Families

- `users`, emits `sendoso.users`, reads `/v1/users`
- `accounts`, emits `sendoso.accounts`, reads `/v1/accounts`
- `records`, emits `sendoso.records`, reads `/v1/records`
- `policies`, emits `sendoso.policies`, reads `/v1/policies`
- `audit_events`, emits `sendoso.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sendoso ./internal/sourceprojection -count=1`
- `make catalog-check`
