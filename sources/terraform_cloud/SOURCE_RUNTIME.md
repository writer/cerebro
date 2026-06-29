# Terraform Cloud

Generated Source Runtime SDK scaffold for `terraform_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/terraform_cloud`
- Health endpoint: `/source-runtimes/health?source_id=terraform_cloud`
- Source health receipt: `sources/terraform_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `terraform_cloud.evidence_cas_reference`

## Families

- `repositories`, emits `terraform_cloud.repositories`, reads `/v1/repositories`
- `users`, emits `terraform_cloud.users`, reads `/v1/users`
- `audit_events`, emits `terraform_cloud.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/terraform_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
