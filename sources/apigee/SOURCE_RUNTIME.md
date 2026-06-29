# Apigee

Generated Source Runtime SDK scaffold for `apigee`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/apigee`
- Health endpoint: `/source-runtimes/health?source_id=apigee`
- Source health receipt: `sources/apigee/source_health_receipt.json`
- EvidenceCAS reference kind: `apigee.evidence_cas_reference`

## Families

- `users`, emits `apigee.users`, reads `/v1/users`
- `projects`, emits `apigee.projects`, reads `/v1/projects`
- `repositories`, emits `apigee.repositories`, reads `/v1/repositories`
- `deployments`, emits `apigee.deployments`, reads `/v1/deployments`
- `audit_events`, emits `apigee.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/apigee ./internal/sourceprojection -count=1`
- `make catalog-check`
