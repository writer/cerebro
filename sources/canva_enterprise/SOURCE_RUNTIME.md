# Canva Enterprise

Generated Source Runtime SDK scaffold for `canva_enterprise`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/canva_enterprise`
- Health endpoint: `/source-runtimes/health?source_id=canva_enterprise`
- Source health receipt: `sources/canva_enterprise/source_health_receipt.json`
- EvidenceCAS reference kind: `canva_enterprise.evidence_cas_reference`

## Families

- `users`, emits `canva_enterprise.users`, reads `/v1/users`
- `groups`, emits `canva_enterprise.groups`, reads `/v1/groups`
- `workspaces`, emits `canva_enterprise.workspaces`, reads `/v1/workspaces`
- `documents`, emits `canva_enterprise.documents`, reads `/v1/documents`
- `audit_events`, emits `canva_enterprise.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/canva_enterprise ./internal/sourceprojection -count=1`
- `make catalog-check`
