# Gong

Generated Source Runtime SDK scaffold for `gong`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gong`
- Health endpoint: `/source-runtimes/health?source_id=gong`
- Source health receipt: `sources/gong/source_health_receipt.json`
- EvidenceCAS reference kind: `gong.evidence_cas_reference`

## Families

- `users`, emits `gong.users`, reads `/v1/users`
- `accounts`, emits `gong.accounts`, reads `/v1/accounts`
- `records`, emits `gong.records`, reads `/v1/records`
- `policies`, emits `gong.policies`, reads `/v1/policies`
- `audit_events`, emits `gong.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/gong ./internal/sourceprojection -count=1`
- `make catalog-check`
