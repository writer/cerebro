# Opsgenie

Generated Source Runtime SDK scaffold for `opsgenie`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/opsgenie`
- Health endpoint: `/source-runtimes/health?source_id=opsgenie`
- Source health receipt: `sources/opsgenie/source_health_receipt.json`
- EvidenceCAS reference kind: `opsgenie.evidence_cas_reference`

## Families

- `users`, emits `opsgenie.users`, reads `/v1/users`
- `tickets`, emits `opsgenie.tickets`, reads `/v1/tickets`
- `audit_events`, emits `opsgenie.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/opsgenie ./internal/sourceprojection -count=1`
- `make catalog-check`
