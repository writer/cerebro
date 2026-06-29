# Workday

Generated Source Runtime SDK scaffold for `workday`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/workday`
- Health endpoint: `/source-runtimes/health?source_id=workday`
- Source health receipt: `sources/workday/source_health_receipt.json`
- EvidenceCAS reference kind: `workday.evidence_cas_reference`

## Families

- `users`, emits `workday.users`, reads `/v1/workers`
- `groups`, emits `workday.groups`, reads `/v1/organizations`
- `audit_events`, emits `workday.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/workday ./internal/sourceprojection -count=1`
- `make catalog-check`
