# Pulumi Cloud

Generated Source Runtime SDK scaffold for `pulumi_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/pulumi_cloud`
- Health endpoint: `/source-runtimes/health?source_id=pulumi_cloud`
- Source health receipt: `sources/pulumi_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `pulumi_cloud.evidence_cas_reference`

## Families

- `repositories`, emits `pulumi_cloud.repositories`, reads `/v1/repositories`
- `users`, emits `pulumi_cloud.users`, reads `/v1/users`
- `audit_events`, emits `pulumi_cloud.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/pulumi_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
