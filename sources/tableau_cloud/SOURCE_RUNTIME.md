# Tableau Cloud

Generated Source Runtime SDK scaffold for `tableau_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/tableau_cloud`
- Health endpoint: `/source-runtimes/health?source_id=tableau_cloud`
- Source health receipt: `sources/tableau_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `tableau_cloud.evidence_cas_reference`

## Families

- `users`, emits `tableau_cloud.users`, reads `/v1/users`
- `accounts`, emits `tableau_cloud.accounts`, reads `/v1/accounts`
- `records`, emits `tableau_cloud.records`, reads `/v1/records`
- `policies`, emits `tableau_cloud.policies`, reads `/v1/policies`
- `audit_events`, emits `tableau_cloud.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/tableau_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
