# Netlify

Generated Source Runtime SDK scaffold for `netlify`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/netlify`
- Health endpoint: `/source-runtimes/health?source_id=netlify`
- Source health receipt: `sources/netlify/source_health_receipt.json`
- EvidenceCAS reference kind: `netlify.evidence_cas_reference`

## Families

- `users`, emits `netlify.users`, reads `/v1/users`
- `projects`, emits `netlify.projects`, reads `/v1/projects`
- `repositories`, emits `netlify.repositories`, reads `/v1/repositories`
- `deployments`, emits `netlify.deployments`, reads `/v1/deployments`
- `audit_events`, emits `netlify.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/netlify ./internal/sourceprojection -count=1`
- `make catalog-check`
