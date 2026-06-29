# Seismic

Generated Source Runtime SDK scaffold for `seismic`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/seismic`
- Health endpoint: `/source-runtimes/health?source_id=seismic`
- Source health receipt: `sources/seismic/source_health_receipt.json`
- EvidenceCAS reference kind: `seismic.evidence_cas_reference`

## Families

- `users`, emits `seismic.users`, reads `/v1/users`
- `accounts`, emits `seismic.accounts`, reads `/v1/accounts`
- `records`, emits `seismic.records`, reads `/v1/records`
- `policies`, emits `seismic.policies`, reads `/v1/policies`
- `audit_events`, emits `seismic.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/seismic ./internal/sourceprojection -count=1`
- `make catalog-check`
