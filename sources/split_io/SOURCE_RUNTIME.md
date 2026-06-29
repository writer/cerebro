# Split.io

Generated Source Runtime SDK scaffold for `split_io`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/split_io`
- Health endpoint: `/source-runtimes/health?source_id=split_io`
- Source health receipt: `sources/split_io/source_health_receipt.json`
- EvidenceCAS reference kind: `split_io.evidence_cas_reference`

## Families

- `users`, emits `split_io.users`, reads `/v1/users`
- `projects`, emits `split_io.projects`, reads `/v1/projects`
- `repositories`, emits `split_io.repositories`, reads `/v1/repositories`
- `deployments`, emits `split_io.deployments`, reads `/v1/deployments`
- `audit_events`, emits `split_io.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/split_io ./internal/sourceprojection -count=1`
- `make catalog-check`
