# Zendesk

Generated Source Runtime SDK scaffold for `zendesk`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zendesk`
- Health endpoint: `/source-runtimes/health?source_id=zendesk`
- Source health receipt: `sources/zendesk/source_health_receipt.json`
- EvidenceCAS reference kind: `zendesk.evidence_cas_reference`

## Families

- `users`, emits `zendesk.users`, reads `/v1/users`
- `tickets`, emits `zendesk.tickets`, reads `/v1/tickets`
- `audit_events`, emits `zendesk.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/zendesk ./internal/sourceprojection -count=1`
- `make catalog-check`
