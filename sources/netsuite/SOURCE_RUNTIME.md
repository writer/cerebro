# NetSuite

Generated Source Runtime SDK scaffold for `netsuite`.

## Runtime input

- Source type: `json_api`
- Auth model: `signature`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/netsuite`
- Health endpoint: `/source-runtimes/health?source_id=netsuite`
- Source health receipt: `sources/netsuite/source_health_receipt.json`
- EvidenceCAS reference kind: `netsuite.evidence_cas_reference`

## Families

- `users`, emits `netsuite.users`, reads `/v1/users`
- `assets`, emits `netsuite.assets`, reads `/v1/records`
- `audit_events`, emits `netsuite.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/netsuite ./internal/sourceprojection -count=1`
- `make catalog-check`
