# Sprout Social

Generated Source Runtime SDK scaffold for `sprout_social`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sprout_social`
- Health endpoint: `/source-runtimes/health?source_id=sprout_social`
- Source health receipt: `sources/sprout_social/source_health_receipt.json`
- EvidenceCAS reference kind: `sprout_social.evidence_cas_reference`

## Families

- `users`, emits `sprout_social.users`, reads `/v1/users`
- `groups`, emits `sprout_social.groups`, reads `/v1/groups`
- `workspaces`, emits `sprout_social.workspaces`, reads `/v1/workspaces`
- `documents`, emits `sprout_social.documents`, reads `/v1/documents`
- `audit_events`, emits `sprout_social.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sprout_social ./internal/sourceprojection -count=1`
- `make catalog-check`
