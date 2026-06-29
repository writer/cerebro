# Degreed

Generated Source Runtime SDK scaffold for `degreed`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/degreed`
- Health endpoint: `/source-runtimes/health?source_id=degreed`
- Source health receipt: `sources/degreed/source_health_receipt.json`
- EvidenceCAS reference kind: `degreed.evidence_cas_reference`

## Families

- `users`, emits `degreed.users`, reads `/v1/users`
- `accounts`, emits `degreed.accounts`, reads `/v1/accounts`
- `records`, emits `degreed.records`, reads `/v1/records`
- `policies`, emits `degreed.policies`, reads `/v1/policies`
- `audit_events`, emits `degreed.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/degreed ./internal/sourceprojection -count=1`
- `make catalog-check`
