# Zoominfo

Generated Source Runtime SDK scaffold for `zoominfo`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zoominfo`
- Health endpoint: `/source-runtimes/health?source_id=zoominfo`
- Source health receipt: `sources/zoominfo/source_health_receipt.json`
- EvidenceCAS reference kind: `zoominfo.evidence_cas_reference`

## Families

- `users`, emits `zoominfo.users`, reads `/v1/users`
- `accounts`, emits `zoominfo.accounts`, reads `/v1/accounts`
- `records`, emits `zoominfo.records`, reads `/v1/records`
- `policies`, emits `zoominfo.policies`, reads `/v1/policies`
- `audit_events`, emits `zoominfo.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zoominfo ./internal/sourceprojection -count=1`
- `make catalog-check`
