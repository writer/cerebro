# Hid Workforce Identity

Generated Source Runtime SDK scaffold for `hid_workforce_identity`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hid_workforce_identity`
- Health endpoint: `/source-runtimes/health?source_id=hid_workforce_identity`
- Source health receipt: `sources/hid_workforce_identity/source_health_receipt.json`
- EvidenceCAS reference kind: `hid_workforce_identity.evidence_cas_reference`

## Families

- `users`, emits `hid_workforce_identity.users`, reads `/v1/users`
- `groups`, emits `hid_workforce_identity.groups`, reads `/v1/groups`
- `roles`, emits `hid_workforce_identity.roles`, reads `/v1/roles`
- `applications`, emits `hid_workforce_identity.applications`, reads `/v1/applications`
- `audit_events`, emits `hid_workforce_identity.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/hid_workforce_identity ./internal/sourceprojection -count=1`
- `make catalog-check`
