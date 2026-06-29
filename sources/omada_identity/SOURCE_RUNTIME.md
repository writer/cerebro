# Omada Identity

Generated Source Runtime SDK scaffold for `omada_identity`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/omada_identity`
- Health endpoint: `/source-runtimes/health?source_id=omada_identity`
- Source health receipt: `sources/omada_identity/source_health_receipt.json`
- EvidenceCAS reference kind: `omada_identity.evidence_cas_reference`

## Families

- `users`, emits `omada_identity.users`, reads `/v1/users`
- `groups`, emits `omada_identity.groups`, reads `/v1/groups`
- `roles`, emits `omada_identity.roles`, reads `/v1/roles`
- `applications`, emits `omada_identity.applications`, reads `/v1/applications`
- `audit_events`, emits `omada_identity.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/omada_identity ./internal/sourceprojection -count=1`
- `make catalog-check`
