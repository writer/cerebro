# Notion

Generated Source Runtime SDK scaffold for `notion`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/notion`
- Health endpoint: `/source-runtimes/health?source_id=notion`
- Source health receipt: `sources/notion/source_health_receipt.json`
- EvidenceCAS reference kind: `notion.evidence_cas_reference`

## Families

- `users`, emits `notion.users`, reads `/v1/users`
- `projects`, emits `notion.projects`, reads `/v1/projects`
- `audit_events`, emits `notion.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/notion ./internal/sourceprojection -count=1`
- `make catalog-check`
