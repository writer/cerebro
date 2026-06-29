# Featurebase

Generated Source Runtime SDK scaffold for `featurebase`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/featurebase`
- Health endpoint: `/source-runtimes/health?source_id=featurebase`
- Source health receipt: `sources/featurebase/source_health_receipt.json`
- EvidenceCAS reference kind: `featurebase.evidence_cas_reference`

## Families

- `users`, emits `featurebase.users`, reads `/v1/users`
- `projects`, emits `featurebase.projects`, reads `/v1/projects`
- `repositories`, emits `featurebase.repositories`, reads `/v1/repositories`
- `deployments`, emits `featurebase.deployments`, reads `/v1/deployments`
- `audit_events`, emits `featurebase.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/featurebase ./internal/sourceprojection -count=1`
- `make catalog-check`
