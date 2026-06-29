# GitLab

Generated Source Runtime SDK scaffold for `gitlab`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gitlab`
- Health endpoint: `/source-runtimes/health?source_id=gitlab`
- Source health receipt: `sources/gitlab/source_health_receipt.json`
- EvidenceCAS reference kind: `gitlab.evidence_cas_reference`

## Families

- `repositories`, emits `gitlab.repositories`, reads `/v1/repositories`
- `users`, emits `gitlab.users`, reads `/v1/users`
- `audit_events`, emits `gitlab.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/gitlab ./internal/sourceprojection -count=1`
- `make catalog-check`
