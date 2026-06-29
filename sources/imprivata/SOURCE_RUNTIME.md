# Imprivata

Generated Source Runtime SDK scaffold for `imprivata`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/imprivata`
- Health endpoint: `/source-runtimes/health?source_id=imprivata`
- Source health receipt: `sources/imprivata/source_health_receipt.json`
- EvidenceCAS reference kind: `imprivata.evidence_cas_reference`

## Families

- `users`, emits `imprivata.users`, reads `/v1/users`
- `groups`, emits `imprivata.groups`, reads `/v1/groups`
- `roles`, emits `imprivata.roles`, reads `/v1/roles`
- `applications`, emits `imprivata.applications`, reads `/v1/applications`
- `audit_events`, emits `imprivata.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/imprivata ./internal/sourceprojection -count=1`
- `make catalog-check`
