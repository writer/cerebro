# Perforce Helix Cloud

Generated Source Runtime SDK scaffold for `perforce_helix_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/perforce_helix_cloud`
- Health endpoint: `/source-runtimes/health?source_id=perforce_helix_cloud`
- Source health receipt: `sources/perforce_helix_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `perforce_helix_cloud.evidence_cas_reference`

## Families

- `users`, emits `perforce_helix_cloud.users`, reads `/v1/users`
- `projects`, emits `perforce_helix_cloud.projects`, reads `/v1/projects`
- `repositories`, emits `perforce_helix_cloud.repositories`, reads `/v1/repositories`
- `deployments`, emits `perforce_helix_cloud.deployments`, reads `/v1/deployments`
- `audit_events`, emits `perforce_helix_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/perforce_helix_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
