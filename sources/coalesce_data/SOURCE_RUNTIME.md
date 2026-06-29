# Coalesce Data

Generated Source Runtime SDK scaffold for `coalesce_data`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/coalesce_data`
- Health endpoint: `/source-runtimes/health?source_id=coalesce_data`
- Source health receipt: `sources/coalesce_data/source_health_receipt.json`
- EvidenceCAS reference kind: `coalesce_data.evidence_cas_reference`

## Families

- `users`, emits `coalesce_data.users`, reads `/v1/users`
- `accounts`, emits `coalesce_data.accounts`, reads `/v1/accounts`
- `records`, emits `coalesce_data.records`, reads `/v1/records`
- `policies`, emits `coalesce_data.policies`, reads `/v1/policies`
- `audit_events`, emits `coalesce_data.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/coalesce_data ./internal/sourceprojection -count=1`
- `make catalog-check`
