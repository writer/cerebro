# Soti Mobicontrol

Generated Source Runtime SDK scaffold for `soti_mobicontrol`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/soti_mobicontrol`
- Health endpoint: `/source-runtimes/health?source_id=soti_mobicontrol`
- Source health receipt: `sources/soti_mobicontrol/source_health_receipt.json`
- EvidenceCAS reference kind: `soti_mobicontrol.evidence_cas_reference`

## Families

- `users`, emits `soti_mobicontrol.users`, reads `/v1/users`
- `groups`, emits `soti_mobicontrol.groups`, reads `/v1/groups`
- `roles`, emits `soti_mobicontrol.roles`, reads `/v1/roles`
- `applications`, emits `soti_mobicontrol.applications`, reads `/v1/applications`
- `audit_events`, emits `soti_mobicontrol.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/soti_mobicontrol ./internal/sourceprojection -count=1`
- `make catalog-check`
