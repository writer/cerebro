# Bitbucket Cloud

Generated Source Runtime SDK scaffold for `bitbucket_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bitbucket_cloud`
- Health endpoint: `/source-runtimes/health?source_id=bitbucket_cloud`
- Source health receipt: `sources/bitbucket_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `bitbucket_cloud.evidence_cas_reference`

## Families

- `repositories`, emits `bitbucket_cloud.repositories`, reads `/v1/repositories`
- `users`, emits `bitbucket_cloud.users`, reads `/v1/users`
- `audit_events`, emits `bitbucket_cloud.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/bitbucket_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
