# Sixsense

Generated Source Runtime SDK scaffold for `sixsense`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sixsense`
- Health endpoint: `/source-runtimes/health?source_id=sixsense`
- Source health receipt: `sources/sixsense/source_health_receipt.json`
- EvidenceCAS reference kind: `sixsense.evidence_cas_reference`

## Families

- `users`, emits `sixsense.users`, reads `/v1/users`
- `accounts`, emits `sixsense.accounts`, reads `/v1/accounts`
- `records`, emits `sixsense.records`, reads `/v1/records`
- `policies`, emits `sixsense.policies`, reads `/v1/policies`
- `audit_events`, emits `sixsense.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sixsense ./internal/sourceprojection -count=1`
- `make catalog-check`
