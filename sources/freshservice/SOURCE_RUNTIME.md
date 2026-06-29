# Freshservice

Generated Source Runtime SDK scaffold for `freshservice`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/freshservice`
- Health endpoint: `/source-runtimes/health?source_id=freshservice`
- Source health receipt: `sources/freshservice/source_health_receipt.json`
- EvidenceCAS reference kind: `freshservice.evidence_cas_reference`

## Families

- `users`, emits `freshservice.users`, reads `/v1/users`
- `tickets`, emits `freshservice.tickets`, reads `/v1/tickets`
- `audit_events`, emits `freshservice.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/freshservice ./internal/sourceprojection -count=1`
- `make catalog-check`
