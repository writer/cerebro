# Contentful

Generated Source Runtime SDK scaffold for `contentful`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/contentful`
- Health endpoint: `/source-runtimes/health?source_id=contentful`
- Source health receipt: `sources/contentful/source_health_receipt.json`
- EvidenceCAS reference kind: `contentful.evidence_cas_reference`

## Families

- `users`, emits `contentful.users`, reads `/v1/users`
- `groups`, emits `contentful.groups`, reads `/v1/groups`
- `workspaces`, emits `contentful.workspaces`, reads `/v1/workspaces`
- `documents`, emits `contentful.documents`, reads `/v1/documents`
- `audit_events`, emits `contentful.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/contentful ./internal/sourceprojection -count=1`
- `make catalog-check`
