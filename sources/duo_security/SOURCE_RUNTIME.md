# Duo Security

Generated Source Runtime SDK scaffold for `duo_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/duo_security`
- Health endpoint: `/source-runtimes/health?source_id=duo_security`
- Source health receipt: `sources/duo_security/source_health_receipt.json`
- EvidenceCAS reference kind: `duo_security.evidence_cas_reference`

## Families

- `users`, emits `duo_security.users`, reads `/v1/users`
- `groups`, emits `duo_security.groups`, reads `/v1/groups`
- `roles`, emits `duo_security.roles`, reads `/v1/roles`
- `applications`, emits `duo_security.applications`, reads `/v1/applications`
- `audit_events`, emits `duo_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/duo_security ./internal/sourceprojection -count=1`
- `make catalog-check`
