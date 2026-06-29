# ServiceNow

Generated Source Runtime SDK scaffold for `servicenow`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/servicenow`
- Health endpoint: `/source-runtimes/health?source_id=servicenow`
- Source health receipt: `sources/servicenow/source_health_receipt.json`
- EvidenceCAS reference kind: `servicenow.evidence_cas_reference`

## Families

- `users`, emits `servicenow.users`, reads `/v1/users`
- `tickets`, emits `servicenow.tickets`, reads `/v1/tickets`
- `audit_events`, emits `servicenow.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/servicenow ./internal/sourceprojection -count=1`
- `make catalog-check`
