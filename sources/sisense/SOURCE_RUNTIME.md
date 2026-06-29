# Sisense

Generated Source Runtime SDK scaffold for `sisense`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sisense`
- Health endpoint: `/source-runtimes/health?source_id=sisense`
- Source health receipt: `sources/sisense/source_health_receipt.json`
- EvidenceCAS reference kind: `sisense.evidence_cas_reference`

## Families

- `users`, emits `sisense.users`, reads `/v1/users`
- `accounts`, emits `sisense.accounts`, reads `/v1/accounts`
- `records`, emits `sisense.records`, reads `/v1/records`
- `policies`, emits `sisense.policies`, reads `/v1/policies`
- `audit_events`, emits `sisense.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sisense ./internal/sourceprojection -count=1`
- `make catalog-check`
