# Mistral AI

Generated Source Runtime SDK scaffold for `mistral`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mistral`
- Health endpoint: `/source-runtimes/health?source_id=mistral`
- Source health receipt: `sources/mistral/source_health_receipt.json`
- EvidenceCAS reference kind: `mistral.evidence_cas_reference`

## Families

- `workspaces`, emits `mistral.workspaces`, reads `/v1/organization/workspaces`
- `api_keys`, emits `mistral.api_keys`, reads `/v1/organization/api-keys`
- `audit_logs`, emits `mistral.audit_logs`, reads `/v1/organization/audit-logs`
- `usage_reports`, emits `mistral.usage_reports`, reads `/v1/organization/usage`

## Tests

- `go test ./sources/mistral ./internal/sourceprojection -count=1`
- `make catalog-check`
