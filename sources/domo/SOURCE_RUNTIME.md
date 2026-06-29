# Domo

Generated Source Runtime SDK scaffold for `domo`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/domo`
- Health endpoint: `/source-runtimes/health?source_id=domo`
- Source health receipt: `sources/domo/source_health_receipt.json`
- EvidenceCAS reference kind: `domo.evidence_cas_reference`

## Families

- `users`, emits `domo.users`, reads `/v1/users`
- `accounts`, emits `domo.accounts`, reads `/v1/accounts`
- `records`, emits `domo.records`, reads `/v1/records`
- `policies`, emits `domo.policies`, reads `/v1/policies`
- `audit_events`, emits `domo.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/domo ./internal/sourceprojection -count=1`
- `make catalog-check`
