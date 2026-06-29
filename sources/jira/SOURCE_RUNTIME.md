# Jira

Generated Source Runtime SDK scaffold for `jira`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/jira`
- Health endpoint: `/source-runtimes/health?source_id=jira`
- Source health receipt: `sources/jira/source_health_receipt.json`
- EvidenceCAS reference kind: `jira.evidence_cas_reference`

## Families

- `users`, emits `jira.users`, reads `/v1/users`
- `projects`, emits `jira.projects`, reads `/v1/projects`
- `audit_events`, emits `jira.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/jira ./internal/sourceprojection -count=1`
- `make catalog-check`
