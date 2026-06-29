# Optimizely Feature Experimentation

Generated Source Runtime SDK scaffold for `optimizely_feature_experimentation`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/optimizely_feature_experimentation`
- Health endpoint: `/source-runtimes/health?source_id=optimizely_feature_experimentation`
- Source health receipt: `sources/optimizely_feature_experimentation/source_health_receipt.json`
- EvidenceCAS reference kind: `optimizely_feature_experimentation.evidence_cas_reference`

## Families

- `users`, emits `optimizely_feature_experimentation.users`, reads `/v1/users`
- `projects`, emits `optimizely_feature_experimentation.projects`, reads `/v1/projects`
- `repositories`, emits `optimizely_feature_experimentation.repositories`, reads `/v1/repositories`
- `deployments`, emits `optimizely_feature_experimentation.deployments`, reads `/v1/deployments`
- `audit_events`, emits `optimizely_feature_experimentation.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/optimizely_feature_experimentation ./internal/sourceprojection -count=1`
- `make catalog-check`
