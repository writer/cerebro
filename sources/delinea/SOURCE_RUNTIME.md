# Delinea

Generated Source Runtime SDK scaffold for `delinea`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/delinea`
- Health endpoint: `/source-runtimes/health?source_id=delinea`
- Source health receipt: `sources/delinea/source_health_receipt.json`
- EvidenceCAS reference kind: `delinea.evidence_cas_reference`

## Families

- `users`, emits `delinea.users`, reads `/v1/users`
- `groups`, emits `delinea.groups`, reads `/v1/groups`
- `roles`, emits `delinea.roles`, reads `/v1/roles`
- `applications`, emits `delinea.applications`, reads `/v1/applications`
- `audit_events`, emits `delinea.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/delinea ./internal/sourceprojection -count=1`
- `make catalog-check`
