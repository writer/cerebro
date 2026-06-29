# Vercel

Generated Source Runtime SDK scaffold for `vercel`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/vercel`
- Health endpoint: `/source-runtimes/health?source_id=vercel`
- Source health receipt: `sources/vercel/source_health_receipt.json`
- EvidenceCAS reference kind: `vercel.evidence_cas_reference`

## Families

- `projects`, emits `vercel.projects`, reads `/v9/projects`
- `deployments`, emits `vercel.deployments`, reads `/v6/deployments`
- `audit_events`, emits `vercel.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/vercel ./internal/sourceprojection -count=1`
- `make catalog-check`
