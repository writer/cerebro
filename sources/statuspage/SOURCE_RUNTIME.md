# Statuspage

Generated Source Runtime SDK scaffold for `statuspage`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/statuspage`
- Health endpoint: `/source-runtimes/health?source_id=statuspage`
- Source health receipt: `sources/statuspage/source_health_receipt.json`
- EvidenceCAS reference kind: `statuspage.evidence_cas_reference`

## Families

- `users`, emits `statuspage.users`, reads `/v1/users`
- `tickets`, emits `statuspage.tickets`, reads `/v1/tickets`
- `audit_events`, emits `statuspage.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/statuspage ./internal/sourceprojection -count=1`
- `make catalog-check`
