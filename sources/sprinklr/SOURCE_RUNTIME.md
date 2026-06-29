# Sprinklr

Generated Source Runtime SDK scaffold for `sprinklr`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sprinklr`
- Health endpoint: `/source-runtimes/health?source_id=sprinklr`
- Source health receipt: `sources/sprinklr/source_health_receipt.json`
- EvidenceCAS reference kind: `sprinklr.evidence_cas_reference`

## Families

- `users`, emits `sprinklr.users`, reads `/v1/users`
- `accounts`, emits `sprinklr.accounts`, reads `/v1/accounts`
- `records`, emits `sprinklr.records`, reads `/v1/records`
- `policies`, emits `sprinklr.policies`, reads `/v1/policies`
- `audit_events`, emits `sprinklr.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sprinklr ./internal/sourceprojection -count=1`
- `make catalog-check`
